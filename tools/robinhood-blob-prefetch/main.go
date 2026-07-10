package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	batchDeliveredTopic = "0x7394f4a19a13c7b92b5bb71033245305946ef78452f7b4986ac1390b5df4ebd7"
	blobDataLocation    = uint64(3)
	blobHexLength       = 2 + 2*131072
)

type config struct {
	listenAddr       string
	l1RPC            string
	sequencerInbox   string
	fromBlock        uint64
	cacheDir         string
	logWorkers       int
	metadataWorkers  int
	metadataBatch    int
	fetchWorkers     int
	remoteBeaconBase string
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error,omitempty"`
}

type batchLog struct {
	BlockNumber string `json:"blockNumber"`
	TxHash      string `json:"transactionHash"`
	LogIndex    string `json:"logIndex"`
	Data        string `json:"data"`
}

type blobJob struct {
	Slot   uint64
	Hashes []string
}

type cacheFile struct {
	Version int               `json:"version"`
	Data    map[string]string `json:"data"`
}

type proxy struct {
	cfg            config
	client         *http.Client
	genesisTime    uint64
	secondsPerSlot uint64
	slotLocks      sync.Map
}

func main() {
	var cfg config
	flag.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:5053", "local beacon proxy listen address")
	flag.StringVar(&cfg.l1RPC, "l1-rpc", "http://192.168.1.3:8545", "Ethereum execution RPC URL")
	flag.StringVar(&cfg.sequencerInbox, "sequencer-inbox", "0xBd0D173EEb87D57A09521c24388a12789F33ba96", "sequencer inbox address")
	flag.Uint64Var(&cfg.fromBlock, "from-block", 24994238, "sequencer inbox deployment block")
	flag.StringVar(&cfg.cacheDir, "cache-dir", "/Volumes/DATA/arbitrum-reth-robinhood/nitro/blob-cache", "Nitro blob cache directory")
	flag.IntVar(&cfg.logWorkers, "log-workers", 4, "parallel eth_getLogs requests")
	flag.IntVar(&cfg.metadataWorkers, "metadata-workers", 6, "parallel local metadata batches")
	flag.IntVar(&cfg.metadataBatch, "metadata-batch", 100, "blob transactions per local JSON-RPC batch")
	flag.IntVar(&cfg.fetchWorkers, "fetch-workers", 4, "parallel archive beacon requests")
	flag.Parse()

	cfg.remoteBeaconBase = strings.TrimRight(os.Getenv("BEACON_URL"), "/")
	if cfg.remoteBeaconBase == "" {
		log.Fatal("BEACON_URL is required")
	}
	if cfg.logWorkers < 1 || cfg.metadataWorkers < 1 || cfg.metadataBatch < 1 || cfg.fetchWorkers < 1 {
		log.Fatal("all worker and batch counts must be positive")
	}
	if err := os.MkdirAll(cfg.cacheDir, 0700); err != nil {
		log.Fatalf("create cache directory: %v", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 64
	transport.MaxIdleConnsPerHost = 32
	transport.IdleConnTimeout = 90 * time.Second
	p := &proxy{
		cfg:    cfg,
		client: &http.Client{Transport: transport, Timeout: 75 * time.Second},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	p.genesisTime, p.secondsPerSlot, err = p.beaconParameters(ctx)
	if err != nil {
		log.Fatalf("read beacon parameters: %v", err)
	}
	log.Printf("beacon parameters: genesis=%d seconds_per_slot=%d", p.genesisTime, p.secondsPerSlot)

	server := &http.Server{Addr: cfg.listenAddr, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("local verified-cache proxy listening on %s", cfg.listenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("proxy server failed: %v", err)
			stop()
		}
	}()

	logs, latest, err := p.discoverBlobLogs(ctx)
	if err != nil {
		log.Fatalf("discover blob batches: %v", err)
	}
	log.Printf("discovered %d blob batches through L1 block %d", len(logs), latest)

	jobs, err := p.enrichJobs(ctx, logs)
	if err != nil {
		log.Fatalf("resolve blob slots and hashes: %v", err)
	}
	log.Printf("resolved %d unique beacon slots", len(jobs))

	failed := p.prefetch(ctx, jobs)
	if failed == 0 {
		log.Printf("historical beacon prefetch complete; proxy remains available")
	} else {
		log.Printf("historical beacon prefetch complete with %d deferred failures; proxy will retry them on demand", failed)
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const blobPrefix = "/eth/v1/beacon/blobs/"
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, blobPrefix) {
		slot, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, blobPrefix), 10, 64)
		if err != nil {
			http.Error(w, "invalid slot", http.StatusBadRequest)
			return
		}
		hashes := r.URL.Query()["versioned_hashes"]
		if len(hashes) == 0 {
			p.forward(w, r)
			return
		}
		data, err := p.getOrFetch(r.Context(), blobJob{Slot: slot, Hashes: hashes})
		if err != nil {
			log.Printf("on-demand slot %d failed: %v", slot, err)
			http.Error(w, "archive beacon fetch failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":                 data,
			"execution_optimistic": false,
			"finalized":            true,
		})
		return
	}
	p.forward(w, r)
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request) {
	u, err := p.remoteURL(r.URL.Path, r.URL.Query())
	if err != nil {
		http.Error(w, "invalid archive beacon URL", http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u, http.NoBody)
	if err != nil {
		http.Error(w, "could not build archive request", http.StatusInternalServerError)
		return
	}
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "archive beacon unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *proxy) beaconParameters(ctx context.Context) (uint64, uint64, error) {
	var genesis struct {
		Data struct {
			GenesisTime string `json:"genesis_time"`
		} `json:"data"`
	}
	if err := p.remoteJSON(ctx, "/eth/v1/beacon/genesis", nil, &genesis); err != nil {
		return 0, 0, err
	}
	genesisTime, err := strconv.ParseUint(genesis.Data.GenesisTime, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse genesis time: %w", err)
	}

	var spec struct {
		Data struct {
			SecondsPerSlot string `json:"SECONDS_PER_SLOT"`
		} `json:"data"`
	}
	if err := p.remoteJSON(ctx, "/eth/v1/config/spec", nil, &spec); err != nil {
		return 0, 0, err
	}
	secondsPerSlot, err := strconv.ParseUint(spec.Data.SecondsPerSlot, 10, 64)
	if err != nil || secondsPerSlot == 0 {
		return 0, 0, fmt.Errorf("parse SECONDS_PER_SLOT: %w", err)
	}
	return genesisTime, secondsPerSlot, nil
}

func (p *proxy) discoverBlobLogs(ctx context.Context) ([]batchLog, uint64, error) {
	var latestHex string
	if err := p.rpcCall(ctx, "eth_blockNumber", []any{}, &latestHex); err != nil {
		return nil, 0, err
	}
	latest, err := parseHexUint64(latestHex)
	if err != nil {
		return nil, 0, err
	}

	type blockRange struct{ from, to uint64 }
	ranges := make(chan blockRange)
	results := make(chan []batchLog)
	errs := make(chan error, p.cfg.logWorkers)
	var wg sync.WaitGroup
	for range p.cfg.logWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockRange := range ranges {
				var found []batchLog
				params := []any{map[string]any{
					"fromBlock": fmt.Sprintf("0x%x", blockRange.from),
					"toBlock":   fmt.Sprintf("0x%x", blockRange.to),
					"address":   p.cfg.sequencerInbox,
					"topics":    []string{batchDeliveredTopic},
				}}
				if err := p.rpcCall(ctx, "eth_getLogs", params, &found); err != nil {
					errs <- fmt.Errorf("logs %d-%d: %w", blockRange.from, blockRange.to, err)
					return
				}
				filtered := found[:0]
				for _, item := range found {
					location, err := dataLocation(item.Data)
					if err != nil {
						errs <- err
						return
					}
					if location == blobDataLocation {
						filtered = append(filtered, item)
					}
				}
				select {
				case results <- filtered:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(ranges)
		for from := p.cfg.fromBlock; from <= latest; {
			to := from + 99999
			if to < from || to > latest {
				to = latest
			}
			select {
			case ranges <- blockRange{from: from, to: to}:
			case <-ctx.Done():
				return
			}
			if to == latest {
				return
			}
			from = to + 1
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var all []batchLog
	for result := range results {
		all = append(all, result...)
	}
	select {
	case err := <-errs:
		return nil, 0, err
	default:
	}
	sort.Slice(all, func(i, j int) bool {
		ib, _ := parseHexUint64(all[i].BlockNumber)
		jb, _ := parseHexUint64(all[j].BlockNumber)
		if ib != jb {
			return ib < jb
		}
		il, _ := parseHexUint64(all[i].LogIndex)
		jl, _ := parseHexUint64(all[j].LogIndex)
		return il < jl
	})
	return all, latest, nil
}

func (p *proxy) enrichJobs(ctx context.Context, logs []batchLog) ([]blobJob, error) {
	type chunkResult struct {
		jobs []blobJob
		err  error
	}
	chunks := make(chan []batchLog)
	results := make(chan chunkResult)
	var wg sync.WaitGroup
	for range p.cfg.metadataWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range chunks {
				jobs, err := p.enrichChunk(ctx, chunk)
				select {
				case results <- chunkResult{jobs: jobs, err: err}:
				case <-ctx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}()
	}
	go func() {
		defer close(chunks)
		for start := 0; start < len(logs); start += p.cfg.metadataBatch {
			end := min(start+p.cfg.metadataBatch, len(logs))
			select {
			case chunks <- logs[start:end]:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var jobs []blobJob
	for result := range results {
		if result.err != nil {
			return nil, result.err
		}
		jobs = append(jobs, result.jobs...)
	}
	return combineJobs(jobs), nil
}

func (p *proxy) enrichChunk(ctx context.Context, logs []batchLog) ([]blobJob, error) {
	requests := make([]rpcRequest, 0, len(logs)*2)
	for i, item := range logs {
		requests = append(requests,
			rpcRequest{JSONRPC: "2.0", ID: i * 2, Method: "eth_getTransactionByHash", Params: []any{item.TxHash}},
			rpcRequest{JSONRPC: "2.0", ID: i*2 + 1, Method: "eth_getBlockByNumber", Params: []any{item.BlockNumber, false}},
		)
	}
	body, err := json.Marshal(requests)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.l1RPC, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("local L1 RPC returned %s", resp.Status)
	}
	var responses []rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&responses); err != nil {
		return nil, err
	}
	byID := make(map[int]rpcResponse, len(responses))
	for _, response := range responses {
		if response.Error != nil {
			return nil, fmt.Errorf("local L1 RPC error %d: %s", response.Error.Code, response.Error.Message)
		}
		byID[response.ID] = response
	}

	jobs := make([]blobJob, 0, len(logs))
	for i := range logs {
		var tx struct {
			BlobVersionedHashes []string `json:"blobVersionedHashes"`
		}
		if err := json.Unmarshal(byID[i*2].Result, &tx); err != nil {
			return nil, fmt.Errorf("decode blob transaction: %w", err)
		}
		if len(tx.BlobVersionedHashes) == 0 {
			return nil, fmt.Errorf("blob batch transaction %s has no blob hashes", logs[i].TxHash)
		}
		var block struct {
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(byID[i*2+1].Result, &block); err != nil {
			return nil, fmt.Errorf("decode L1 block: %w", err)
		}
		timestamp, err := parseHexUint64(block.Timestamp)
		if err != nil {
			return nil, err
		}
		if timestamp < p.genesisTime {
			return nil, fmt.Errorf("L1 timestamp predates beacon genesis")
		}
		jobs = append(jobs, blobJob{
			Slot:   (timestamp - p.genesisTime) / p.secondsPerSlot,
			Hashes: tx.BlobVersionedHashes,
		})
	}
	return jobs, nil
}

func (p *proxy) prefetch(ctx context.Context, jobs []blobJob) int {
	pending := make([]blobJob, 0, len(jobs))
	for _, job := range jobs {
		if _, ok := p.readCache(job); !ok {
			pending = append(pending, job)
		}
	}
	log.Printf("cache already has %d/%d slots; prefetching %d with concurrency %d", len(jobs)-len(pending), len(jobs), len(pending), p.cfg.fetchWorkers)
	if len(pending) == 0 {
		return 0
	}

	jobCh := make(chan blobJob)
	resultCh := make(chan error)
	var wg sync.WaitGroup
	for range p.cfg.fetchWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				var err error
				for attempt := 0; attempt < 5; attempt++ {
					_, err = p.getOrFetch(ctx, job)
					if err == nil {
						break
					}
					select {
					case <-time.After(time.Duration(1<<attempt) * time.Second):
					case <-ctx.Done():
						return
					}
				}
				select {
				case resultCh <- err:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobCh)
		for _, job := range pending {
			select {
			case jobCh <- job:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	started := time.Now()
	completed := 0
	failed := 0
	for err := range resultCh {
		completed++
		if err != nil {
			failed++
			log.Printf("prefetch request failed after retries: %v", err)
		}
		if completed%100 == 0 || completed == len(pending) {
			elapsed := time.Since(started).Seconds()
			rate := float64(completed) / elapsed
			eta := time.Duration(float64(len(pending)-completed)/rate) * time.Second
			log.Printf("prefetch progress: %d/%d (%.2f slots/s, eta %s, failures %d)", completed, len(pending), rate, eta.Round(time.Second), failed)
		}
	}
	return failed
}

func (p *proxy) getOrFetch(ctx context.Context, job blobJob) ([]string, error) {
	lock := p.lockForSlot(job.Slot)
	lock.Lock()
	defer lock.Unlock()
	if data, ok := p.readCache(job); ok {
		return data, nil
	}
	data, err := p.fetchRemote(ctx, job)
	if err != nil {
		return nil, err
	}
	if err := p.writeCache(job, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *proxy) fetchRemote(ctx context.Context, job blobJob) ([]string, error) {
	query := make(url.Values)
	for _, hash := range job.Hashes {
		query.Add("versioned_hashes", hash)
	}
	var response struct {
		Data []string `json:"data"`
	}
	if err := p.remoteJSON(ctx, fmt.Sprintf("/eth/v1/beacon/blobs/%d", job.Slot), query, &response); err != nil {
		return nil, err
	}
	if len(response.Data) != len(job.Hashes) {
		return nil, fmt.Errorf("slot %d: expected %d blobs, got %d", job.Slot, len(job.Hashes), len(response.Data))
	}
	for i, blob := range response.Data {
		if len(blob) != blobHexLength || !strings.HasPrefix(blob, "0x") {
			return nil, fmt.Errorf("slot %d blob %d has invalid encoded length %d", job.Slot, i, len(blob))
		}
	}
	return response.Data, nil
}

func (p *proxy) readCache(job blobJob) ([]string, bool) {
	data, err := os.ReadFile(filepath.Join(p.cfg.cacheDir, strconv.FormatUint(job.Slot, 10)))
	if err != nil {
		return nil, false
	}
	var cached cacheFile
	if json.Unmarshal(data, &cached) != nil || cached.Version != 1 {
		return nil, false
	}
	result := make([]string, len(job.Hashes))
	for i, hash := range job.Hashes {
		blob, ok := cached.Data[strings.ToLower(hash)]
		if !ok || len(blob) != blobHexLength {
			return nil, false
		}
		result[i] = blob
	}
	return result, true
}

func (p *proxy) writeCache(job blobJob, blobs []string) error {
	filePath := filepath.Join(p.cfg.cacheDir, strconv.FormatUint(job.Slot, 10))
	cached := cacheFile{Version: 1, Data: make(map[string]string, len(job.Hashes))}
	if data, err := os.ReadFile(filePath); err == nil {
		_ = json.Unmarshal(data, &cached)
		if cached.Data == nil {
			cached.Data = make(map[string]string, len(job.Hashes))
		}
		cached.Version = 1
	}
	for i, hash := range job.Hashes {
		cached.Data[strings.ToLower(hash)] = blobs[i]
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(p.cfg.cacheDir, ".blob-prefetch-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filePath)
}

func (p *proxy) lockForSlot(slot uint64) *sync.Mutex {
	lock, _ := p.slotLocks.LoadOrStore(slot, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func (p *proxy) remoteJSON(ctx context.Context, requestPath string, query url.Values, target any) error {
	u, err := p.remoteURL(requestPath, query)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("archive beacon request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("archive beacon returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode archive beacon response: %w", err)
	}
	return nil
}

func (p *proxy) remoteURL(requestPath string, query url.Values) (string, error) {
	u, err := url.Parse(p.cfg.remoteBeaconBase)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(requestPath, "/")
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (p *proxy) rpcCall(ctx context.Context, method string, params any, target any) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.l1RPC, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local L1 RPC returned %s", resp.Status)
	}
	var response rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("local L1 RPC error %d: %s", response.Error.Code, response.Error.Message)
	}
	return json.Unmarshal(response.Result, target)
}

func combineJobs(jobs []blobJob) []blobJob {
	bySlot := make(map[uint64]map[string]struct{}, len(jobs))
	for _, job := range jobs {
		if bySlot[job.Slot] == nil {
			bySlot[job.Slot] = make(map[string]struct{})
		}
		for _, hash := range job.Hashes {
			bySlot[job.Slot][strings.ToLower(hash)] = struct{}{}
		}
	}
	combined := make([]blobJob, 0, len(bySlot))
	for slot, hashes := range bySlot {
		job := blobJob{Slot: slot, Hashes: make([]string, 0, len(hashes))}
		for hash := range hashes {
			job.Hashes = append(job.Hashes, hash)
		}
		sort.Strings(job.Hashes)
		combined = append(combined, job)
	}
	sort.Slice(combined, func(i, j int) bool { return combined[i].Slot < combined[j].Slot })
	return combined
}

func dataLocation(data string) (uint64, error) {
	raw := strings.TrimPrefix(data, "0x")
	if len(raw) < 64 {
		return 0, fmt.Errorf("short SequencerBatchDelivered event data")
	}
	word := strings.TrimLeft(raw[len(raw)-64:], "0")
	if word == "" {
		return 0, nil
	}
	return strconv.ParseUint(word, 16, 64)
}

func parseHexUint64(value string) (uint64, error) {
	raw := strings.TrimPrefix(value, "0x")
	if raw == "" {
		return 0, fmt.Errorf("empty hex quantity")
	}
	return strconv.ParseUint(raw, 16, 64)
}
