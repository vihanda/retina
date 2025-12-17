// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProbeType defines the type of probe to perform
// +kubebuilder:validation:Enum=HTTP;HTTPS;TCP
type ProbeType string

const (
	ProbeTypeHTTP  ProbeType = "HTTP"
	ProbeTypeHTTPS ProbeType = "HTTPS"
	ProbeTypeTCP   ProbeType = "TCP"
)

// ProbeTarget defines a single endpoint to probe
type ProbeTarget struct {
	// Name is a friendly name for this probe target
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Endpoint is the target URL or host:port to probe
	// Examples: "https://google.com", "example.com:443", "10.0.0.1:80"
	// +kubebuilder:validation:Required
	Endpoint string `json:"endpoint"`

	// Protocol specifies the probe type (HTTP, HTTPS, TCP)
	// +kubebuilder:default=HTTP
	Protocol ProbeType `json:"protocol"`

	// Interval is the time between probes
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern="^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
	// +kubebuilder:default="10s"
	Interval metav1.Duration `json:"interval,omitempty"`

	// Timeout for each probe
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern="^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
	// +kubebuilder:default="5s"
	Timeout metav1.Duration `json:"timeout,omitempty"`

	// ExpectedStatusCode for HTTP/HTTPS probes (default: 200)
	// +optional
	ExpectedStatusCode *int `json:"expectedStatusCode,omitempty"`

	// Headers to include in HTTP/HTTPS requests
	// +optional
	Headers map[string]string `json:"headers,omitempty"`
}

// ProbeConfigurationSpec defines the desired state of ProbeConfiguration
type ProbeConfigurationSpec struct {
	// Targets is a list of endpoints to probe
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Targets []ProbeTarget `json:"targets"`

	// NodeSelector restricts which nodes run probes (optional)
	// If not specified, all nodes with Retina agent will probe
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// ProbeConfigurationStatus defines the observed state of ProbeConfiguration
type ProbeConfigurationStatus struct {
	// Phase represents the current phase of the probe configuration
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides additional details about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// LastUpdateTime is when the status was last updated
	// +optional
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`

	// LastProbeTime is when the last probe was executed
	// +optional
	LastProbeTime *metav1.Time `json:"lastProbeTime,omitempty"`

	// ActiveProbes is the number of currently active probe routines
	// +optional
	ActiveProbes int32 `json:"activeProbes,omitempty"`

	// Conditions represent the latest available observations of the probe configuration's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Targets",type=integer,JSONPath=`.spec.targets`
// +kubebuilder:printcolumn:name="Active",type=integer,JSONPath=`.status.activeProbes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ProbeConfiguration is the Schema for the probeconfigurations API
type ProbeConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProbeConfigurationSpec   `json:"spec,omitempty"`
	Status ProbeConfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProbeConfigurationList contains a list of ProbeConfiguration
type ProbeConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProbeConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ProbeConfiguration{}, &ProbeConfigurationList{})
}
