/*
Copyright 2015 Google Inc. All rights reserved.

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

package container

import (
	"sync"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/types"
)

// ReadinessManager maintains the readiness information(probe results) of
// containers over time to allow for implementation of health thresholds.
// This manager is thread-safe, no locks are necessary for the caller.
type ReadinessManager struct {
	// guards states
	sync.RWMutex
	states map[types.UID]bool
}

// NewReadinessManager creates ane returns a readiness manager with empty
// contents.
func NewReadinessManager() *ReadinessManager {
	return &ReadinessManager{states: make(map[types.UID]bool)}
}

// GetReadiness returns the readiness value for the container with the given ID.
// If the readiness value is found, returns it.
// If the readiness is not found, returns false.
func (r *ReadinessManager) GetReadiness(id types.UID) bool {
	r.RLock()
	defer r.RUnlock()
	state, found := r.states[id]
	return state && found
}

// SetReadiness sets the readiness value for the container with the given ID.
func (r *ReadinessManager) SetReadiness(id types.UID, value bool) {
	r.Lock()
	defer r.Unlock()
	r.states[id] = value
}

// RemoveReadiness clears the readiness value for the container with the given ID.
func (r *ReadinessManager) RemoveReadiness(id types.UID) {
	r.Lock()
	defer r.Unlock()
	delete(r.states, id)
}
