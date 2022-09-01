//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by conversion-gen. DO NOT EDIT.

package v1

import (
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	clusterresourceoverride "k8s.io/kubernetes/openshift-kube-apiserver/admission/autoscaling/apis/clusterresourceoverride"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*ClusterResourceOverrideConfig)(nil), (*clusterresourceoverride.ClusterResourceOverrideConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1_ClusterResourceOverrideConfig_To_clusterresourceoverride_ClusterResourceOverrideConfig(a.(*ClusterResourceOverrideConfig), b.(*clusterresourceoverride.ClusterResourceOverrideConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*clusterresourceoverride.ClusterResourceOverrideConfig)(nil), (*ClusterResourceOverrideConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_clusterresourceoverride_ClusterResourceOverrideConfig_To_v1_ClusterResourceOverrideConfig(a.(*clusterresourceoverride.ClusterResourceOverrideConfig), b.(*ClusterResourceOverrideConfig), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1_ClusterResourceOverrideConfig_To_clusterresourceoverride_ClusterResourceOverrideConfig(in *ClusterResourceOverrideConfig, out *clusterresourceoverride.ClusterResourceOverrideConfig, s conversion.Scope) error {
	out.LimitCPUToMemoryPercent = in.LimitCPUToMemoryPercent
	out.CPURequestToLimitPercent = in.CPURequestToLimitPercent
	out.MemoryRequestToLimitPercent = in.MemoryRequestToLimitPercent
	return nil
}

// Convert_v1_ClusterResourceOverrideConfig_To_clusterresourceoverride_ClusterResourceOverrideConfig is an autogenerated conversion function.
func Convert_v1_ClusterResourceOverrideConfig_To_clusterresourceoverride_ClusterResourceOverrideConfig(in *ClusterResourceOverrideConfig, out *clusterresourceoverride.ClusterResourceOverrideConfig, s conversion.Scope) error {
	return autoConvert_v1_ClusterResourceOverrideConfig_To_clusterresourceoverride_ClusterResourceOverrideConfig(in, out, s)
}

func autoConvert_clusterresourceoverride_ClusterResourceOverrideConfig_To_v1_ClusterResourceOverrideConfig(in *clusterresourceoverride.ClusterResourceOverrideConfig, out *ClusterResourceOverrideConfig, s conversion.Scope) error {
	out.LimitCPUToMemoryPercent = in.LimitCPUToMemoryPercent
	out.CPURequestToLimitPercent = in.CPURequestToLimitPercent
	out.MemoryRequestToLimitPercent = in.MemoryRequestToLimitPercent
	return nil
}

// Convert_clusterresourceoverride_ClusterResourceOverrideConfig_To_v1_ClusterResourceOverrideConfig is an autogenerated conversion function.
func Convert_clusterresourceoverride_ClusterResourceOverrideConfig_To_v1_ClusterResourceOverrideConfig(in *clusterresourceoverride.ClusterResourceOverrideConfig, out *ClusterResourceOverrideConfig, s conversion.Scope) error {
	return autoConvert_clusterresourceoverride_ClusterResourceOverrideConfig_To_v1_ClusterResourceOverrideConfig(in, out, s)
}
