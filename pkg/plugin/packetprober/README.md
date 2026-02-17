# Create Kind Cluster
kind create cluster --name retina-test --wait 60s

Build Agent & Init Docker Images
cd /home/vihanda/lindev/retina

# Build agent image (includes packetprober plugin)
docker build -f controller/Dockerfile --platform=linux/amd64 --target=agent -t retina-agent:local .

# Build init image
docker build -f controller/Dockerfile --platform=linux/amd64 --target=init -t retina-init:local .

# Load Images into Kind
kind load docker-image retina-agent:local --name retina-test
kind load docker-image retina-init:local --name retina-test


# Label Node for Probe Runner
# The packetprober requires probe-runner=true on each node it should run probes from:

kubectl label node retina-test-control-plane probe-runner=true

#  Deploy Retina via Helm (with packetprober enabled)
helm upgrade --install retina ./deploy/standard/manifests/controller/helm/retina/ \
  --namespace kube-system \
  --set image.repository=retina-agent \
  --set image.initRepository=retina-init \
  --set image.tag=local \
  --set image.pullPolicy=Never \
  --set logLevel=debug \
  --set os.windows=false \
  --set operator.enabled=false \
  --set 'enabledPlugin_linux=\[\"dropreason\"\,\"packetforward\"\,\"linuxutil\"\,\"dns\"\,\"packetprober\"\]'

NAME: retina
LAST DEPLOYED: Mon Feb 16 06:34:12 2026
NAMESPACE: kube-system
STATUS: deployed
REVISION: 1


# Wait for Pod Ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=retina -n kube-system --timeout=120s


# Verify Plugin Initialization (Startup Logs)

POD=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=retina -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n kube-system "$POD" -c retina | grep -i -E "packetprober|scheduler|watcher|node.*label|starting plugin"

ts=2026-02-16T06:34:17.363Z level=info caller=packetprober/packetprober_linux.go:136
    msg="Stopping packetprober plugin"

ts=2026-02-16T06:34:17.363Z level=info caller=scheduler/scheduler.go:149
    msg="All probes stopped"

ts=2026-02-16T06:34:17.363Z level=info caller=packetprober/packetprober_linux.go:93
    msg="Initializing packetprober plugin"

ts=2026-02-16T06:34:17.366Z level=info caller=node/watcher.go:85
    msg="Fetched node labels" nodeName=retina-test-control-plane labelCount=7

ts=2026-02-16T06:34:17.367Z level=info caller=packetprober/packetprober_linux.go:99
    msg="Running on node" nodeName=retina-test-control-plane

ts=2026-02-16T06:34:17.367Z level=info caller=pluginmanager/pluginmanager.go:167
    msg="starting plugin packetprober"

ts=2026-02-16T06:34:17.367Z level=info caller=packetprober/packetprober_linux.go:106
    msg="Starting packetprober plugin"

ts=2026-02-16T06:34:18.383Z level=info caller=watcher/watcher.go:150
    msg="Synced existing ProbeConfigurations" count=0



# Create ProbeConfiguration
kubectl apply -f /home/vihanda/lindev/retina/examples/probe-config-example.yaml

probeconfiguration.retina.sh/example-probes created

# probe-config-example.yaml

apiVersion: retina.sh/v1alpha1
kind: ProbeConfiguration
metadata:
  name: example-probes
spec:
  targets:
    - name: google-https
      endpoint: https://www.google.com
      protocol: HTTPS
      interval: 30s
      timeout: 10s
    - name: microsoft-https
      endpoint: https://www.microsoft.com
      protocol: HTTPS
      interval: 30s
      timeout: 10s
    - name: kubernetes-https
      endpoint: https://kubernetes.io
      protocol: HTTPS
      interval: 30s
      timeout: 10s


# Verify Probes Started (Logs)
kubectl logs -n kube-system "$POD" -c retina --since=30s | grep -i -E "probe|schedule|config|target"

ts=2026-02-16T06:41:28.374Z level=info caller=watcher/watcher.go:232
    msg="ProbeConfiguration added" name=example-probes

ts=2026-02-16T06:41:28.374Z level=info caller=packetprober/packetprober_linux.go:151
    msg="Adding new ProbeConfiguration" name=example-probes targets=3

ts=2026-02-16T06:41:28.374Z level=info caller=packetprober/packetprober_linux.go:169
    msg="Node matches selector, starting probes"
    name=example-probes nodeName=retina-test-control-plane

ts=2026-02-16T06:41:28.374Z level=info caller=scheduler/scheduler.go:109
    msg="Started probe" name=google-https
    endpoint=https://www.google.com protocol=HTTPS interval=30

ts=2026-02-16T06:41:28.374Z level=info caller=scheduler/scheduler.go:109
    msg="Started probe" name=microsoft-https
    endpoint=https://www.microsoft.com protocol=HTTPS interval=30

ts=2026-02-16T06:41:28.374Z level=info caller=scheduler/scheduler.go:109
    msg="Started probe" name=kubernetes-https
    endpoint=https://kubernetes.io protocol=HTTPS interval=30

# Verify Probe Execution (Logs)
kubectl logs -n kube-system "$POD" -c retina --since=35s | grep "Probe completed"

ts=2026-02-16T06:42:28.729Z level=debug caller=scheduler/scheduler.go:222
    msg="Probe completed" target=kubernetes-https
    endpoint=https://kubernetes.io success=true latency=0.273768889 error_type=

ts=2026-02-16T06:42:28.927Z level=debug caller=scheduler/scheduler.go:222
    msg="Probe completed" target=google-https
    endpoint=https://www.google.com success=true latency=0.471619908 error_type=

ts=2026-02-16T06:42:34.691Z level=debug caller=scheduler/scheduler.go:222
    msg="Probe completed" target=microsoft-https
    endpoint=https://www.microsoft.com success=false latency=0.040852734
    error_type=status_code_302

ts=2026-02-16T06:42:58.740Z level=debug caller=scheduler/scheduler.go:222
    msg="Probe completed" target=kubernetes-https
    endpoint=https://kubernetes.io success=true latency=0.244188537 error_type=

ts=2026-02-16T06:42:58.895Z level=debug caller=scheduler/scheduler.go:222
    msg="Probe completed" target=google-https
    endpoint=https://www.google.com success=true latency=0.399701347 error_type=


# Port-Forward to Agent Pod (Metrics via Prometheus)
POD=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=retina -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward -n kube-system "$POD" 10093:10093 &