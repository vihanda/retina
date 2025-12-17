// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build linux

package packetprober

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	retinav1alpha1 "github.com/microsoft/retina/crd/api/v1alpha1"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	"github.com/microsoft/retina/pkg/plugin/registry"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	name = "packetprober"
)

// Plugin configuration
type packetprober struct {
	cfg    *kcfg.Config
	l      *log.ZapLogger
	client client.Client

	// Node information
	nodeName   string
	nodeLabels map[string]string

	// Active probe configurations
	probeConfigs map[string]*retinav1alpha1.ProbeConfiguration
	probeMutex   sync.RWMutex

	// Active probe goroutines
	probeStopChans map[string]chan struct{}
	probeWg        sync.WaitGroup

	externalChannel chan *v1.Event
}

func init() {
	registry.Add(name, New)
}

func New(cfg *kcfg.Config) registry.Plugin {
	return &packetprober{
		cfg:            cfg,
		l:              log.Logger().Named(name),
		probeConfigs:   make(map[string]*retinav1alpha1.ProbeConfiguration),
		probeStopChans: make(map[string]chan struct{}),
	}
}

func (p *packetprober) Name() string {
	return name
}

func (p *packetprober) Generate(ctx context.Context) error {
	// No eBPF code generation needed for this plugin
	return nil
}

func (p *packetprober) Compile(ctx context.Context) error {
	// No eBPF code compilation needed for this plugin
	return nil
}

func (p *packetprober) Init() error {
	p.l.Info("Initializing packetprober plugin")
	
	// Get node name from environment or hostname
	p.nodeName = os.Getenv("NODE_NAME")
	if p.nodeName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			p.l.Warn("Failed to get hostname, using 'unknown'", zap.Error(err))
			p.nodeName = "unknown"
		} else {
			p.nodeName = hostname
		}
	}
	p.l.Info("Running on node", zap.String("nodeName", p.nodeName))

	// Initialize node labels map
	p.nodeLabels = make(map[string]string)
	
	// Initialize metrics
	if err := p.initMetrics(); err != nil {
		return fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return nil
}

func (p *packetprober) Start(ctx context.Context) error {
	p.l.Info("Starting packetprober plugin")

	// Fetch node labels for matching
	if err := p.fetchNodeLabels(ctx); err != nil {
		p.l.Error("Failed to fetch node labels, continuing without label matching", zap.Error(err))
	}

	// Start watching for ProbeConfiguration CRDs
	go p.watchProbeConfigurations(ctx)

	// Wait for context cancellation
	<-ctx.Done()
	
	// Stop all active probes
	p.stopAllProbes()
	
	return nil
}

func (p *packetprober) Stop() error {
	p.l.Info("Stopping packetprober plugin")
	p.stopAllProbes()
	return nil
}

func (p *packetprober) SetupChannel(ch chan *v1.Event) error {
	p.externalChannel = ch
	return nil
}

// fetchNodeLabels retrieves the current node's labels from Kubernetes API
func (p *packetprober) fetchNodeLabels(ctx context.Context) error {
	cfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get Kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	node, err := clientset.CoreV1().Nodes().Get(ctx, p.nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get node %s: %w", p.nodeName, err)
	}

	p.probeMutex.Lock()
	p.nodeLabels = node.Labels
	p.probeMutex.Unlock()

	p.l.Info("Fetched node labels",
		zap.String("nodeName", p.nodeName),
		zap.Int("labelCount", len(node.Labels)))

	return nil
}

// matchesNodeSelector checks if the current node matches the given node selector
func (p *packetprober) matchesNodeSelector(nodeSelector map[string]string) bool {
	p.probeMutex.RLock()
	defer p.probeMutex.RUnlock()

	// REQUIRED: Node must have probe-runner=true label to run any probes
	probeRunnerValue, hasProbeRunner := p.nodeLabels["probe-runner"]
	if !hasProbeRunner || probeRunnerValue != "true" {
		return false
	}

	// If no additional node selector specified, probe-runner=true is sufficient
	if len(nodeSelector) == 0 {
		return true
	}

	// Check if all additional selector labels match node labels
	for key, value := range nodeSelector {
		nodeValue, exists := p.nodeLabels[key]
		if !exists || nodeValue != value {
			return false
		}
	}

	return true
}

func (p *packetprober) initMetrics() error {
	// Metrics will be defined in a separate metrics file
	// probe_success_total, probe_failure_total, probe_latency_seconds, etc.
	return nil
}

func (p *packetprober) stopAllProbes() {
	p.probeMutex.Lock()
	defer p.probeMutex.Unlock()

	// Stop all probe goroutines
	for key, stopChan := range p.probeStopChans {
		close(stopChan)
		delete(p.probeStopChans, key)
	}

	// Wait for all probes to finish
	p.probeWg.Wait()
	
	p.l.Info("All probes stopped")
}

// watchProbeConfigurations watches for ProbeConfiguration CRD changes using Kubernetes Watch API
func (p *packetprober) watchProbeConfigurations(ctx context.Context) {
	p.l.Info("Starting to watch ProbeConfiguration CRDs")

	// Get the Kubernetes REST config
	cfg, err := config.GetConfig()
	if err != nil {
		p.l.Error("Failed to get Kubernetes config", zap.Error(err))
		return
	}

	// Create a REST client for our CRD
	restClient, err := p.createRestClient(cfg)
	if err != nil {
		p.l.Error("Failed to create REST client", zap.Error(err))
		return
	}

	// First, list existing ProbeConfigurations to get current state
	p.l.Info("Listing existing ProbeConfiguration CRDs")
	if err := p.listExistingConfigs(ctx, restClient); err != nil {
		p.l.Error("Failed to list existing ProbeConfigurations", zap.Error(err))
	}

	// Start watching for changes
	for {
		select {
		case <-ctx.Done():
			p.l.Info("Stopping ProbeConfiguration watch")
			return
		default:
			// Watch for ProbeConfiguration changes
			watcher, err := restClient.Get().
				Resource("probeconfigurations").
				VersionedParams(&metav1.ListOptions{
					Watch: true,
				}, metav1.ParameterCodec).
				Watch(ctx)

			if err != nil {
				p.l.Error("Failed to create watcher, retrying in 10s", zap.Error(err))
				time.Sleep(10 * time.Second)
				continue
			}

			p.handleWatchEvents(ctx, watcher)
			watcher.Stop()

			// If watch closed, retry after a delay
			time.Sleep(5 * time.Second)
		}
	}
}

// createRestClient creates a REST client for ProbeConfiguration CRD
func (p *packetprober) createRestClient(cfg *rest.Config) (*rest.RESTClient, error) {
	// Configure the REST client for our CRD
	crdConfig := *cfg
	crdConfig.GroupVersion = &retinav1alpha1.GroupVersion
	crdConfig.APIPath = "/apis"
	crdConfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	// Add the CRD types to the scheme
	if err := retinav1alpha1.AddToScheme(scheme.Scheme); err != nil {
		return nil, fmt.Errorf("failed to add to scheme: %w", err)
	}

	return rest.RESTClientFor(&crdConfig)
}

// listExistingConfigs lists and starts probes for existing ProbeConfigurations
func (p *packetprober) listExistingConfigs(ctx context.Context, restClient *rest.RESTClient) error {
	result := &retinav1alpha1.ProbeConfigurationList{}
	
	err := restClient.Get().
		Resource("probeconfigurations").
		Do(ctx).
		Into(result)

	if err != nil {
		return err
	}

	p.l.Info("Found existing ProbeConfigurations", zap.Int("count", len(result.Items)))

	// Start probes for each existing configuration
	for i := range result.Items {
		config := &result.Items[i]
		if err := p.OnProbeAdd(config); err != nil {
			p.l.Error("Failed to start probes for existing config",
				zap.String("config", config.Name),
				zap.Error(err))
		}
	}

	return nil
}

// handleWatchEvents processes watch events from the Kubernetes API
func (p *packetprober) handleWatchEvents(ctx context.Context, watcher watch.Interface) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				p.l.Info("Watch channel closed, will reconnect")
				return
			}

			config, ok := event.Object.(*retinav1alpha1.ProbeConfiguration)
			if !ok {
				p.l.Warn("Received non-ProbeConfiguration object")
				continue
			}

			switch event.Type {
			case watch.Added:
				p.l.Info("ProbeConfiguration added", zap.String("name", config.Name))
				if err := p.OnProbeAdd(config); err != nil {
					p.l.Error("Failed to handle add event",
						zap.String("config", config.Name),
						zap.Error(err))
				}

			case watch.Modified:
				p.l.Info("ProbeConfiguration modified", zap.String("name", config.Name))
				if err := p.OnProbeUpdate(config); err != nil {
					p.l.Error("Failed to handle update event",
						zap.String("config", config.Name),
						zap.Error(err))
				}

			case watch.Deleted:
				p.l.Info("ProbeConfiguration deleted", zap.String("name", config.Name))
				if err := p.OnProbeDelete(config); err != nil {
					p.l.Error("Failed to handle delete event",
						zap.String("config", config.Name),
						zap.Error(err))
				}

			case watch.Error:
				p.l.Error("Watch error event", zap.Any("object", event.Object))
			}
		}
	}
}


// OnProbeAdd is called when a new ProbeConfiguration is created
func (p *packetprober) OnProbeAdd(probeConfig *retinav1alpha1.ProbeConfiguration) error {
	p.l.Info("Adding new ProbeConfiguration",
		zap.String("name", probeConfig.Name),
		zap.Int("targets", len(probeConfig.Spec.Targets)))

	// Check if this node should run the probes based on node selector
	if !p.matchesNodeSelector(probeConfig.Spec.NodeSelector) {
		p.l.Info("Node does not match selector, skipping ProbeConfiguration",
			zap.String("name", probeConfig.Name),
			zap.String("nodeName", p.nodeName),
			zap.Any("nodeSelector", probeConfig.Spec.NodeSelector))
		return nil
	}

	p.l.Info("Node matches selector, starting probes",
		zap.String("name", probeConfig.Name),
		zap.String("nodeName", p.nodeName))

	p.probeMutex.Lock()
	p.probeConfigs[probeConfig.Name] = probeConfig
	p.probeMutex.Unlock()

	// Start probes for all targets
	for _, target := range probeConfig.Spec.Targets {
		p.startProbe(probeConfig, target)
	}

	return nil
}

// OnProbeUpdate is called when a ProbeConfiguration is updated
func (p *packetprober) OnProbeUpdate(probeConfig *retinav1alpha1.ProbeConfiguration) error {
	p.l.Info("Updating ProbeConfiguration",
		zap.String("name", probeConfig.Name),
		zap.Int("targets", len(probeConfig.Spec.Targets)))

	// Check if this node should run the probes based on node selector
	if !p.matchesNodeSelector(probeConfig.Spec.NodeSelector) {
		p.l.Info("Node no longer matches selector, stopping probes",
			zap.String("name", probeConfig.Name),
			zap.String("nodeName", p.nodeName),
			zap.Any("nodeSelector", probeConfig.Spec.NodeSelector))
		
		// Stop all probes for this configuration since node doesn't match anymore
		p.stopProbesForConfig(probeConfig.Name)
		
		// Remove from stored configs
		p.probeMutex.Lock()
		delete(p.probeConfigs, probeConfig.Name)
		p.probeMutex.Unlock()
		
		return nil
	}

	p.l.Info("Node matches selector, updating probes",
		zap.String("name", probeConfig.Name),
		zap.String("nodeName", p.nodeName))

	// Stop all probes for this configuration
	p.stopProbesForConfig(probeConfig.Name)

	// Update the stored configuration
	p.probeMutex.Lock()
	p.probeConfigs[probeConfig.Name] = probeConfig
	p.probeMutex.Unlock()

	// Start new probes
	for _, target := range probeConfig.Spec.Targets {
		p.startProbe(probeConfig, target)
	}

	return nil
}

// OnProbeDelete is called when a ProbeConfiguration is deleted
func (p *packetprober) OnProbeDelete(probeConfig *retinav1alpha1.ProbeConfiguration) error {
	p.l.Info("Deleting ProbeConfiguration", zap.String("name", probeConfig.Name))

	// Stop all probes for this configuration
	p.stopProbesForConfig(probeConfig.Name)

	// Remove from stored configurations
	p.probeMutex.Lock()
	delete(p.probeConfigs, probeConfig.Name)
	p.probeMutex.Unlock()

	return nil
}

// stopProbesForConfig stops all probes associated with a specific configuration
func (p *packetprober) stopProbesForConfig(configName string) {
	p.probeMutex.Lock()
	defer p.probeMutex.Unlock()

	prefix := configName + "/"
	for key, stopChan := range p.probeStopChans {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			p.l.Info("Stopping probe", zap.String("probe", key))
			close(stopChan)
			delete(p.probeStopChans, key)
		}
	}
}

// startProbe starts a probe routine for a specific target
func (p *packetprober) startProbe(probeConfig *retinav1alpha1.ProbeConfiguration, target retinav1alpha1.ProbeTarget) {
	probeKey := fmt.Sprintf("%s/%s", probeConfig.Name, target.Name)

	// Check if probe is already running
	p.probeMutex.Lock()
	if _, exists := p.probeStopChans[probeKey]; exists {
		p.probeMutex.Unlock()
		p.l.Debug("Probe already running", zap.String("probe", probeKey))
		return
	}

	stopChan := make(chan struct{})
	p.probeStopChans[probeKey] = stopChan
	p.probeMutex.Unlock()

	p.probeWg.Add(1)
	go func() {
		defer p.probeWg.Done()
		p.runProbeLoop(target, stopChan)
	}()

	p.l.Info("Started probe", 
		zap.String("name", target.Name),
		zap.String("endpoint", target.Endpoint),
		zap.String("protocol", string(target.Protocol)),
		zap.Duration("interval", target.Interval.Duration))
}

// runProbeLoop executes probes at the specified interval
func (p *packetprober) runProbeLoop(target retinav1alpha1.ProbeTarget, stopChan chan struct{}) {
	interval := target.Interval.Duration
	if interval == 0 {
		interval = 10 * time.Second // default
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			p.l.Info("Stopping probe", zap.String("target", target.Name))
			return
		case <-ticker.C:
			p.executeProbe(target)
		}
	}
}

// executeProbe performs a single probe
func (p *packetprober) executeProbe(target retinav1alpha1.ProbeTarget) {
	startTime := time.Now()
	var success bool
	var errorType string

	switch target.Protocol {
	case retinav1alpha1.ProbeTypeHTTP, retinav1alpha1.ProbeTypeHTTPS:
		success, errorType = p.probeHTTP(target)
	case retinav1alpha1.ProbeTypeTCP:
		success, errorType = p.probeTCP(target)
	default:
		p.l.Error("Unknown probe type", zap.String("protocol", string(target.Protocol)))
		return
	}

	latency := time.Since(startTime).Seconds()

	// Update metrics
	p.recordProbeMetrics(target, success, latency, errorType)

	// Log the result
	p.l.Debug("Probe completed",
		zap.String("target", target.Name),
		zap.String("endpoint", target.Endpoint),
		zap.Bool("success", success),
		zap.Float64("latency_seconds", latency),
		zap.String("error_type", errorType))
}

// probeHTTP performs an HTTP/HTTPS probe
func (p *packetprober) probeHTTP(target retinav1alpha1.ProbeTarget) (bool, string) {
	timeout := target.Timeout.Duration
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing; make configurable in production
			},
		},
	}

	req, err := http.NewRequest("GET", target.Endpoint, nil)
	if err != nil {
		return false, "request_creation_failed"
	}

	// Add custom headers
	for key, value := range target.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, "timeout"
		}
		return false, "network_error"
	}
	defer resp.Body.Close()

	// Check expected status code
	expectedStatus := 200
	if target.ExpectedStatusCode != nil {
		expectedStatus = *target.ExpectedStatusCode
	}

	if resp.StatusCode == expectedStatus {
		return true, ""
	}

	return false, fmt.Sprintf("status_code_%d", resp.StatusCode)
}

// probeTCP performs a TCP connection probe
func (p *packetprober) probeTCP(target retinav1alpha1.ProbeTarget) (bool, string) {
	timeout := target.Timeout.Duration
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	conn, err := net.DialTimeout("tcp", target.Endpoint, timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false, "timeout"
		}
		return false, "connection_refused"
	}
	defer conn.Close()

	return true, ""
}

// recordProbeMetrics updates Prometheus metrics
func (p *packetprober) recordProbeMetrics(target retinav1alpha1.ProbeTarget, success bool, latency float64, errorType string) {
	labels := []string{
		target.Name,             // probe_name
		target.Endpoint,         // endpoint
		string(target.Protocol), // protocol
	}

	// Always increment total counter
	metrics.ProbeTotalCounter.WithLabelValues(labels...).Inc()

	if success {
		// Record latency in milliseconds (only on success)
		latencyMs := latency * 1000 // Convert seconds to milliseconds
		metrics.ProbeLatencyGauge.WithLabelValues(labels...).Set(latencyMs)
	} else {
		// Increment failure counter with error type
		failureLabels := append(labels, errorType) // add error_type
		metrics.ProbeFailureCounter.WithLabelValues(failureLabels...).Inc()
	}
}
