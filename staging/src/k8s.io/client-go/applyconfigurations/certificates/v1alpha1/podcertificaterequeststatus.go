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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// PodCertificateRequestStatusApplyConfiguration represents a declarative configuration of the PodCertificateRequestStatus type for use
// with apply.
type PodCertificateRequestStatusApplyConfiguration struct {
	Conditions       []v1.ConditionApplyConfiguration `json:"conditions,omitempty"`
	CertificateChain *string                          `json:"certificateChain,omitempty"`
	IssuedAt         *metav1.Time                     `json:"issuedAt,omitempty"`
	NotBefore        *metav1.Time                     `json:"notBefore,omitempty"`
	BeginRefreshAt   *metav1.Time                     `json:"beginRefreshAt,omitempty"`
	NotAfter         *metav1.Time                     `json:"notAfter,omitempty"`
}

// PodCertificateRequestStatusApplyConfiguration constructs a declarative configuration of the PodCertificateRequestStatus type for use with
// apply.
func PodCertificateRequestStatus() *PodCertificateRequestStatusApplyConfiguration {
	return &PodCertificateRequestStatusApplyConfiguration{}
}

// WithConditions adds the given value to the Conditions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Conditions field.
func (b *PodCertificateRequestStatusApplyConfiguration) WithConditions(values ...*v1.ConditionApplyConfiguration) *PodCertificateRequestStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithConditions")
		}
		b.Conditions = append(b.Conditions, *values[i])
	}
	return b
}

// WithCertificateChain sets the CertificateChain field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CertificateChain field is set to the value of the last call.
func (b *PodCertificateRequestStatusApplyConfiguration) WithCertificateChain(value string) *PodCertificateRequestStatusApplyConfiguration {
	b.CertificateChain = &value
	return b
}

// WithIssuedAt sets the IssuedAt field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the IssuedAt field is set to the value of the last call.
func (b *PodCertificateRequestStatusApplyConfiguration) WithIssuedAt(value metav1.Time) *PodCertificateRequestStatusApplyConfiguration {
	b.IssuedAt = &value
	return b
}

// WithNotBefore sets the NotBefore field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NotBefore field is set to the value of the last call.
func (b *PodCertificateRequestStatusApplyConfiguration) WithNotBefore(value metav1.Time) *PodCertificateRequestStatusApplyConfiguration {
	b.NotBefore = &value
	return b
}

// WithBeginRefreshAt sets the BeginRefreshAt field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the BeginRefreshAt field is set to the value of the last call.
func (b *PodCertificateRequestStatusApplyConfiguration) WithBeginRefreshAt(value metav1.Time) *PodCertificateRequestStatusApplyConfiguration {
	b.BeginRefreshAt = &value
	return b
}

// WithNotAfter sets the NotAfter field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NotAfter field is set to the value of the last call.
func (b *PodCertificateRequestStatusApplyConfiguration) WithNotAfter(value metav1.Time) *PodCertificateRequestStatusApplyConfiguration {
	b.NotAfter = &value
	return b
}
