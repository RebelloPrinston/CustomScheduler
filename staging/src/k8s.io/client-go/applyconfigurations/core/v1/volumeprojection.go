/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// VolumeProjectionApplyConfiguration represents a declarative configuration of the VolumeProjection type for use
// with apply.
type VolumeProjectionApplyConfiguration struct {
	Secret              *SecretProjectionApplyConfiguration              `json:"secret,omitempty"`
	DownwardAPI         *DownwardAPIProjectionApplyConfiguration         `json:"downwardAPI,omitempty"`
	ConfigMap           *ConfigMapProjectionApplyConfiguration           `json:"configMap,omitempty"`
	ServiceAccountToken *ServiceAccountTokenProjectionApplyConfiguration `json:"serviceAccountToken,omitempty"`
	ClusterTrustBundle  *ClusterTrustBundleProjectionApplyConfiguration  `json:"clusterTrustBundle,omitempty"`
	PodCertificate      *PodCertificateProjectionApplyConfiguration      `json:"podCertificate,omitempty"`
}

// VolumeProjectionApplyConfiguration constructs a declarative configuration of the VolumeProjection type for use with
// apply.
func VolumeProjection() *VolumeProjectionApplyConfiguration {
	return &VolumeProjectionApplyConfiguration{}
}

// WithSecret sets the Secret field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Secret field is set to the value of the last call.
func (b *VolumeProjectionApplyConfiguration) WithSecret(value *SecretProjectionApplyConfiguration) *VolumeProjectionApplyConfiguration {
	b.Secret = value
	return b
}

// WithDownwardAPI sets the DownwardAPI field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DownwardAPI field is set to the value of the last call.
func (b *VolumeProjectionApplyConfiguration) WithDownwardAPI(value *DownwardAPIProjectionApplyConfiguration) *VolumeProjectionApplyConfiguration {
	b.DownwardAPI = value
	return b
}

// WithConfigMap sets the ConfigMap field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ConfigMap field is set to the value of the last call.
func (b *VolumeProjectionApplyConfiguration) WithConfigMap(value *ConfigMapProjectionApplyConfiguration) *VolumeProjectionApplyConfiguration {
	b.ConfigMap = value
	return b
}

// WithServiceAccountToken sets the ServiceAccountToken field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ServiceAccountToken field is set to the value of the last call.
func (b *VolumeProjectionApplyConfiguration) WithServiceAccountToken(value *ServiceAccountTokenProjectionApplyConfiguration) *VolumeProjectionApplyConfiguration {
	b.ServiceAccountToken = value
	return b
}

// WithClusterTrustBundle sets the ClusterTrustBundle field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClusterTrustBundle field is set to the value of the last call.
func (b *VolumeProjectionApplyConfiguration) WithClusterTrustBundle(value *ClusterTrustBundleProjectionApplyConfiguration) *VolumeProjectionApplyConfiguration {
	b.ClusterTrustBundle = value
	return b
}

// WithPodCertificate sets the PodCertificate field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PodCertificate field is set to the value of the last call.
func (b *VolumeProjectionApplyConfiguration) WithPodCertificate(value *PodCertificateProjectionApplyConfiguration) *VolumeProjectionApplyConfiguration {
	b.PodCertificate = value
	return b
}
