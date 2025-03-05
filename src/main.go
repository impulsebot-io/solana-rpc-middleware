package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

// Configuration struct for the middleware
type Config struct {
	LocalRPC            string `yaml:"localRpc"`
	ListenAddr          string `yaml:"listenAddr"`
	NodeCheckInterval   int    `yaml:"nodeCheckInterval"`
	HealthCheckInterval int    `yaml:"healthCheckInterval"`
	MaxRetries          int    `yaml:"maxRetries"`
	MaxSlotsBehinds     int    `yaml:"maxSlotsBehind"`
	Services           []Service `yaml:"services"`
	AuthMethods        AuthConfig `yaml:"auth"`
}

// Service configuration
type Service struct {
	Name       string `yaml:"name"`
	Path       string `yaml:"path"`
	TargetPort int    `yaml:"targetPort"`
}

// Auth configuration
type AuthConfig struct {
	EnableTokenAuth   bool     `yaml:"enableTokenAuth"`
	Tokens            []string `yaml:"tokens"`
	EnableIPWhitelist bool     `yaml:"enableIPWhitelist"`
	WhitelistedIPs    []string `yaml:"whitelistedIPs"`
}

// SolanaNode represents a Solana RPC endpoint
type SolanaNode struct {
	URL       string
	IsLocal   bool
	Available bool
	Synced    bool
	SlotLag   int
	LastCheck time.Time
	mutex     sync.RWMutex
}

// NodeManager manages the status of all Solana nodes
type NodeManager struct {
	nodes               []*SolanaNode
	mutex               sync.RWMutex
	nodeCheckInterval   time.Duration
	healthCheckInterval time.Duration
	maxSlotsBehind      int
}

// RPCRequest structure for Solana JSON-RPC requests
type RPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      interface{} `json:"id"`
}

// RPCResponse structure for Solana JSON-RPC responses
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// RPCError structure for errors in RPC responses
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var (
	configPath  = flag.String("config", "config.yaml", "Path to configuration file")
	config      Config
	nodeManager *NodeManager
	logger      *log.Logger
)

func main() {
	flag.Parse()

	// Set up logging
	logger = log.New(os.Stdout, "[SOLANA-RPC-MIDDLEWARE] ", log.LstdFlags)
	logger.Println("Starting Solana RPC Middleware")

	// Load configuration
	if err := loadConfig(*configPath); err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize node manager
	nodeManager = newNodeManager()
	nodeManager.addNode(config.LocalRPC, true)

	// Start node discovery and health checks
	go nodeManager.startNodeDiscovery()
	go nodeManager.startHealthChecks()

	// Set up HTTP router
	router := mux.NewRouter()

	// Register the main Solana RPC handler
	router.PathPrefix("/").HandlerFunc(handleRPCRequest)

	// Start servers for each service
	for _, service := range config.Services {
		startServiceServer(service)
	}

	// Set up main server
	srv := &http.Server{
		Addr:    config.ListenAddr,
		Handler: router,
	}

	// Start the server in a goroutine
	go func() {
		logger.Printf("Server listening on %s", config.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("Server shutdown failed: %v", err)
	}

	logger.Println("Server stopped")
}

// Load configuration from YAML file
func loadConfig(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read config file: %v", err)
	}

	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return fmt.Errorf("could not parse config file: %v", err)
	}

	if config.NodeCheckInterval <= 0 {
		config.NodeCheckInterval = 5 // Default to 5 minutes
	}

	if config.HealthCheckInterval <= 0 {
		config.HealthCheckInterval = 30 // Default to 30 seconds
	}

	if config.MaxRetries <= 0 {
		config.MaxRetries = 3 // Default to 3 retries
	}

	if config.MaxSlotsBehinds <= 0 {
		config.MaxSlotsBehinds = 30 // Default to 30 slots
	}

	return nil
}

// Create a new NodeManager
func newNodeManager() *NodeManager {
	return &NodeManager{
		nodes:               make([]*SolanaNode, 0),
		nodeCheckInterval:   time.Duration(config.NodeCheckInterval) * time.Minute,
		healthCheckInterval: time.Duration(config.HealthCheckInterval) * time.Second,
		maxSlotsBehind:      config.MaxSlotsBehinds,
	}
}

// Add a node to the manager
func (m *NodeManager) addNode(url string, isLocal bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if node already exists
	for _, node := range m.nodes {
		if node.URL == url {
			return
		}
	}

	m.nodes = append(m.nodes, &SolanaNode{
		URL:       url,
		IsLocal:   isLocal,
		Available: false,
		Synced:    false,
		SlotLag:   0,
		LastCheck: time.Time{},
	})
}

// Get the best available node
func (m *NodeManager) getBestNode() *SolanaNode {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// First check if local node is available and synced
	for _, node := range m.nodes {
		node.mutex.RLock()
		if node.IsLocal && node.Available && node.Synced {
			node.mutex.RUnlock()
			return node
		}
		node.mutex.RUnlock()
	}

	// If local node is not available, get available and synced fallback nodes
	var availableNodes []*SolanaNode
	for _, node := range m.nodes {
		node.mutex.RLock()
		if !node.IsLocal && node.Available && node.Synced {
			availableNodes = append(availableNodes, node)
		}
		node.mutex.RUnlock()
	}

	if len(availableNodes) == 0 {
		return nil
	}

	// Return a random available node
	return availableNodes[rand.Intn(len(availableNodes))]
}

// Start periodic node discovery
func (m *NodeManager) startNodeDiscovery() {
	// Run discovery immediately at startup
	m.discoverNodes()

	// Set up periodic discovery
	ticker := time.NewTicker(m.nodeCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.discoverNodes()
	}
}

// Discover Solana nodes using solana gossip
func (m *NodeManager) discoverNodes() {
	logger.Println("Starting Solana node discovery...")

	// Run 'solana gossip' command to get a list of nodes
	cmd := exec.Command("solana", "gossip", "--url", "https://api.mainnet-beta.solana.com", "--output", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Printf("Error running solana gossip command: %v", err)
		return
	}

	// Parse the output to extract RPC URLs
	nodes := extractRPCNodesFromGossip(string(output))
	nodeCount := len(nodes)
	logger.Printf("Discovered %d nodes from gossip", nodeCount)

	// Add all discovered nodes to the manager
	for _, nodeURL := range nodes {
		m.addNode(nodeURL, false)
	}

	// Check health of all nodes
	m.checkAllNodes()
}

// Extract RPC node URLs from solana gossip output
func extractRPCNodesFromGossip(output string) []string {
	var nodes []string
	lines := strings.Split(output, "\n")

	// Regular expression to match IP addresses with ports
	ipPortRegex := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)`)

	for _, line := range lines {
		if strings.Contains(line, "rpc") {
			matches := ipPortRegex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) >= 3 {
					// Use the extracted IP and port
					nodeURL := fmt.Sprintf("http://%s:%s", match[1], match[2])
					nodes = append(nodes, nodeURL)
				}
			}
		}
	}

	return nodes
}

// Start periodic health checks
func (m *NodeManager) startHealthChecks() {
	ticker := time.NewTicker(m.healthCheckInterval)
	defer ticker.Stop()

	// Run an initial check
	m.checkAllNodes()

	for range ticker.C {
		m.checkAllNodes()
	}
}

// Check health for all nodes
func (m *NodeManager) checkAllNodes() {
	m.mutex.RLock()
	nodesToCheck := make([]*SolanaNode, len(m.nodes))
	copy(nodesToCheck, m.nodes)
	m.mutex.RUnlock()

	logger.Printf("Checking health of %d nodes", len(nodesToCheck))

	// First get the highest slot from all nodes
	highestSlot := m.getHighestSlot(nodesToCheck)
	if highestSlot < 0 {
		logger.Println("Failed to determine highest slot, skipping health checks")
		return
	}

	logger.Printf("Highest slot across all nodes: %d", highestSlot)

	// Check all nodes in parallel
	var wg sync.WaitGroup
	for _, node := range nodesToCheck {
		wg.Add(1)
		go func(node *SolanaNode) {
			defer wg.Done()
			m.checkNodeHealth(node, highestSlot)
		}(node)
	}
	wg.Wait()

	// Log summary
	m.mutex.RLock()
	var syncedCount, availableCount int
	for _, node := range m.nodes {
		node.mutex.RLock()
		if node.Available {
			availableCount++
			if node.Synced {
				syncedCount++
			}
		}
		node.mutex.RUnlock()
	}
	m.mutex.RUnlock()

	logger.Printf("Health check complete: %d/%d nodes available, %d synced",
		      availableCount, len(m.nodes), syncedCount)
}

// Get the current mainnet slot from Solana mainnet API
func getMainnetSlot() (int64, error) {
	mainnetURL := "https://api.mainnet-beta.solana.com"
	logger.Printf("Fetching current slot from Solana mainnet: %s", mainnetURL)

	request := RPCRequest{
		JSONRPC: "2.0",
		Method:  "getSlot",
		Params:  []interface{}{},
		ID:      1,
	}

	response, err := sendJSONRPCRequest(mainnetURL, request)
	if err != nil {
		return -1, fmt.Errorf("failed to get mainnet slot: %v", err)
	}

	if response.Error != nil {
		return -1, fmt.Errorf("mainnet RPC error: %s", response.Error.Message)
	}

	// Parse the slot from response
	switch v := response.Result.(type) {
		case float64:
			return int64(v), nil
		case int64:
			return v, nil
		case json.Number:
			return v.Int64()
		case string:
			return strconv.ParseInt(v, 10, 64)
		default:
			return -1, fmt.Errorf("unexpected slot type: %T", v)
	}
}

// Get highest slot from all nodes
func (m *NodeManager) getHighestSlot(nodes []*SolanaNode) int64 {
	// Get the reference slot from mainnet
	mainnetSlot, err := getMainnetSlot()
	if err != nil {
		logger.Printf("Warning: %v. Will determine highest slot from available nodes only.", err)
	} else {
		logger.Printf("Current mainnet slot: %d", mainnetSlot)
	}

	type slotResult struct {
		slot  int64
		err   error
		node  string
	}

	results := make(chan slotResult, len(nodes))

	// Query slots from all nodes in parallel
	for _, node := range nodes {
		go func(node *SolanaNode) {
			slot, err := getSlot(node.URL)
			results <- slotResult{slot, err, node.URL}
		}(node)
	}

	// Collect results and find highest slot
	var highestSlot int64 = -1
	var highestNode string

	// Start with mainnet slot if available
	if mainnetSlot > 0 {
		highestSlot = mainnetSlot
		highestNode = "mainnet"
	}

	// Compare with local nodes
	validNodeCount := 0
	for i := 0; i < len(nodes); i++ {
		result := <-results
		if result.err == nil && result.slot > 0 {
			validNodeCount++
			if result.slot > highestSlot {
				highestSlot = result.slot
				highestNode = result.node
			}
		}
	}

	if highestSlot > 0 {
		logger.Printf("Highest slot %d found on %s (collected from %d/%d nodes)",
			      highestSlot, highestNode, validNodeCount, len(nodes))
		return highestSlot
	}

	logger.Println("Failed to determine highest slot from any source")
	return -1
}

// Check if a node is healthy and synced relative to the highest known slot
func (m *NodeManager) checkNodeHealth(node *SolanaNode, highestSlot int64) {
	// Start with defaults
	available := false
	synced := false
	slotLag := m.maxSlotsBehind + 1 // Default to being out of sync

	// Check if node is reachable and get its slot
	slot, err := getSlot(node.URL)
	if err == nil && slot > 0 {
		available = true
		slotLag = int(highestSlot - slot)

		// Node is synced if it's not too far behind
		if slotLag <= m.maxSlotsBehind {
			// Perform an additional test: Validate getTokenAccountBalance
			if testTokenAccountBalance(node.URL) {
				synced = true
			}
		}
	}

	node.mutex.Lock()
	node.Available = available
	node.Synced = synced
	node.SlotLag = slotLag
	node.LastCheck = time.Now()
	node.mutex.Unlock()

	// Log status
	var logStatus string
	if !available {
		logStatus = "offline"
	} else if synced {
		logStatus = fmt.Sprintf("synced (slot lag: %d)", slotLag)
	} else {
		logStatus = fmt.Sprintf("behind (slot lag: %d)", slotLag)
	}

	nodeType := "fallback"
	if node.IsLocal {
		nodeType = "local"
	}

	logger.Printf("Node health: %s node %s is %s", nodeType, node.URL, logStatus)
}

// Test if the node correctly responds to getTokenAccountBalance
func testTokenAccountBalance(nodeURL string) bool {
	testMint := "H5Wuy51jEAV9mrDFUVbNsrSMcBckgHCqmc1r45e7ztVo"
	request := RPCRequest{
		JSONRPC: "2.0",
		Method:  "getTokenAccountBalance",
		Params:  []interface{}{testMint},
		ID:      1,
	}

	response, err := sendJSONRPCRequest(nodeURL, request)
	if err != nil {
		logger.Printf("RPC node %s failed getTokenAccountBalance check: %v", nodeURL, err)
		return false
	}

	if response.Error != nil {
		logger.Printf("RPC node %s returned error for getTokenAccountBalance: %s", nodeURL, response.Error.Message)
		return false
	}

	logger.Printf("RPC node %s passed getTokenAccountBalance check.", nodeURL)
	return true
}

// Get the current slot from a Solana node
func getSlot(nodeURL string) (int64, error) {
	request := RPCRequest{
		JSONRPC: "2.0",
		Method:  "getSlot",
		Params:  []interface{}{},
		ID:      1,
	}

	response, err := sendJSONRPCRequest(nodeURL, request)
	if err != nil {
		return -1, err
	}

	if response.Error != nil {
		return -1, fmt.Errorf("RPC error: %s", response.Error.Message)
	}

	// Parse the slot from response
	switch v := response.Result.(type) {
		case float64:
			return int64(v), nil
		case int64:
			return v, nil
		case json.Number:
			return v.Int64()
		case string:
			return strconv.ParseInt(v, 10, 64)
		default:
			return -1, fmt.Errorf("unexpected slot type: %T", v)
	}
}

// Handle RPC requests
func handleRPCRequest(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Process the request based on method
	if r.Method == http.MethodPost {
		handleRPCPost(w, r)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Handle POST requests to the RPC endpoint
func handleRPCPost(w http.ResponseWriter, r *http.Request) {
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse RPC request
	var rpcRequest RPCRequest
	if err := json.Unmarshal(body, &rpcRequest); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	// Get the best node to forward the request to
	bestNode := nodeManager.getBestNode()
	if bestNode == nil {
		errResponse := RPCResponse{
			JSONRPC: "2.0",
			Error: &RPCError{
				Code:    -32603,
				Message: "All Solana nodes are unavailable",
			},
			ID: rpcRequest.ID,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(errResponse)
		return
	}

	// Forward the request to the selected node with retries
	var response *RPCResponse
	var forwardErr error

	for i := 0; i < config.MaxRetries; i++ {
		response, forwardErr = forwardRPCRequest(bestNode.URL, body)

		if forwardErr == nil && response != nil && response.Error == nil {
			// Success, send the response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			responseJSON, _ := json.Marshal(response)
			w.Write(responseJSON)
			return
		}

		// If we failed, get another node and retry
		bestNode = nodeManager.getBestNode()
		if bestNode == nil {
			break
		}

		logger.Printf("Retry %d/%d: Forwarding to %s", i+1, config.MaxRetries, bestNode.URL)
	}

	// All retries failed
	errResponse := RPCResponse{
		JSONRPC: "2.0",
		Error: &RPCError{
			Code:    -32603,
			Message: "Failed to get response from Solana nodes after retries",
		},
		ID: rpcRequest.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(w).Encode(errResponse)
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: false},
		MaxIdleConns:          100,  // Allow up to 100 idle connections
		MaxIdleConnsPerHost:   50,   // Limit max idle connections per host
		IdleConnTimeout:       90 * time.Second,  // Close idle connections after 90s
		DisableKeepAlives:     false, // Ensure connections are reused
	},
}

// Forward an RPC request to a node
func forwardRPCRequest(nodeURL string, body []byte) (*RPCResponse, error) {
	req, err := http.NewRequest("POST", nodeURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	// Use persistent `httpClient` instead of creating a new client per request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	var rpcResponse RPCResponse
	if err := json.Unmarshal(respBody, &rpcResponse); err != nil {
		return nil, err
	}

	return &rpcResponse, nil
}

// Send a JSON-RPC request to a node
func sendJSONRPCRequest(nodeURL string, request RPCRequest) (*RPCResponse, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return forwardRPCRequest(nodeURL, reqBody)
}

// Check if the request is authenticated
func isAuthenticated(r *http.Request) bool {
	// If no auth methods are enabled, allow all
	if !config.AuthMethods.EnableTokenAuth && !config.AuthMethods.EnableIPWhitelist {
		return true
	}

	// Check token authentication
	if config.AuthMethods.EnableTokenAuth {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			for _, validToken := range config.AuthMethods.Tokens {
				if token == validToken {
					return true
				}
			}
		}
	}

	// Check IP whitelist
	if config.AuthMethods.EnableIPWhitelist {
		ip := getClientIP(r)
		for _, whitelistedIP := range config.AuthMethods.WhitelistedIPs {
			if ip == whitelistedIP {
				return true
			}
		}
	}

	return false
}

// Get client IP address
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first (for clients behind proxies)
	forwardedFor := r.Header.Get("X-Forwarded-For")
		if forwardedFor != "" {
			// X-Forwarded-For can contain multiple IPs, use the first one
			ips := strings.Split(forwardedFor, ",")
			return strings.TrimSpace(ips[0])
		}

		// Try X-Real-IP header
		realIP := r.Header.Get("X-Real-IP")
		if realIP != "" {
			return realIP
		}

		// Fall back to RemoteAddr
		ip := r.RemoteAddr
		// Remove port if present
		if strings.Contains(ip, ":") {
			ip, _, _ = strings.Cut(ip, ":")
		}
		return ip
}

// Start a service server
func startServiceServer(service Service) {
	targetURL, err := url.Parse(fmt.Sprintf("http://localhost:%d", service.TargetPort))
	if err != nil {
		logger.Fatalf("Failed to parse target URL for service %s: %v", service.Name, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	router := mux.NewRouter()

	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", service.Path),
		Handler: router,
	}

	go func() {
		logger.Printf("Starting service %s on port %s", service.Name, service.Path)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start service %s: %v", service.Name, err)
		}
	}()
}
