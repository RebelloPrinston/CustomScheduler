/*
Copyright 2019 The Kubernetes Authors.

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

package config

// PodGCControllerConfiguration contains elements describing PodGCController.
type PodGCControllerConfiguration struct {
	// terminatedPodGCThreshold is the number of terminated pods that can exist
	// before the terminated pod garbage collector starts deleting terminated pods.
	// If <= 0, the terminated pod garbage collector is disabled.
	TerminatedPodGCThreshold int32
	// When enable the feature gate PodGCDeleteAllTerminatedPods, and set DeleteAllTerminatedPods to true,
	// TerminatedPodGCThreshold will be ignored，pod garbage collector will delete all terminated pods. [default=false]
	DeleteAllTerminatedPods bool
}
