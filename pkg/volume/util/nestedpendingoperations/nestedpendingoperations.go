/*
Copyright 2016 The Kubernetes Authors.

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

/*
Package nestedpendingoperations is a modified implementation of
pkg/util/goroutinemap. It implements a data structure for managing go routines
by volume/pod name. It prevents the creation of new go routines if an existing
go routine for the volume already exists. It also allows multiple operations to
execute in parallel for the same volume as long as they are operating on
different pods.
*/
package nestedpendingoperations

import (
	"fmt"
	"sync"

	k8sRuntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/util/goroutinemap/exponentialbackoff"
	volumetypes "k8s.io/kubernetes/pkg/volume/util/types"
)

// NestedPendingOperations defines the supported set of operations.
type NestedPendingOperations interface {

	// Run adds the concatenation of volumeName, podName, and nodeName to the list
	// of running operations and spawns a new go routine to run
	// generatedOperations.

	// volumeName, podName, and nodeName collectively form the operation key.
	// The following forms of operation keys are supported (two keys are designed
	// to be "matched" if we want to serialize their operations):
	// - volumeName empty, podName and nodeName could be anything
	//   This key does not match with any keys.
	// - volumeName exists, podName empty, nodeName empty
	//   This key matches all other keys with the same volumeName.
	// - volumeName exists, podName exists, nodeName empty
	//   This key matches with:
	//   - the same volumeName and podName
	//   - the same volumeName, but empty podName
	// - volumeName exists, podName empty, nodeName exists
	//   This key matches with:
	//   - the same volumeName and nodeName
	//   - the same volumeName but empty nodeName

	// If there is no operation with a matching key, the operation is allowed to
	// proceed.
	// If an operation with a matching key exists and the previous operation is
	// running, an AlreadyExists error is returned.
	// If an operation with a matching key exists and the previous operation
	// failed:
	// - If the previous operation has the same
	//   generatedOperations.operationName:
	//   - If the full exponential backoff period is satisfied, the operation is
	//     allowed to proceed.
	//   - Otherwise, an ExponentialBackoff error is returned.
	// - Otherwise, exponential backoff is reset and operation is allowed to
	//   proceed.

	// Once the operation is complete, the go routine is terminated. If the
	// operation succeeded, its corresponding key is removed from the list of
	// executing operations, allowing a new operation to be started with the key
	// without error. If it failed, the key remains and the exponential
	// backoff status is updated.
	// TODO (verult) update comment
	Run(opKey volumetypes.OperationKey, generatedOperations volumetypes.GeneratedOperations) error

	// Wait blocks until all operations are completed. This is typically
	// necessary during tests - the test should wait until all operations finish
	// and evaluate results after that.
	Wait()

	// IsOperationPending returns true if an operation for the given volumeName
	// and one of podName or nodeName is pending, otherwise it returns false
	IsOperationPending(opKey volumetypes.OperationKey) bool
}

// NewNestedPendingOperations returns a new instance of NestedPendingOperations.
func NewNestedPendingOperations(exponentialBackOffOnError bool) NestedPendingOperations {
	g := &nestedPendingOperations{
		operations:                []operation{},
		exponentialBackOffOnError: exponentialBackOffOnError,
	}
	g.cond = sync.NewCond(&g.lock)
	return g
}

type nestedPendingOperations struct {
	operations                []operation
	exponentialBackOffOnError bool
	cond                      *sync.Cond
	lock                      sync.RWMutex
}

type operation struct {
	key              volumetypes.OperationKey
	operationName    string
	operationPending bool
	expBackoff       exponentialbackoff.ExponentialBackoff
}

func (grm *nestedPendingOperations) Run(
	opKey volumetypes.OperationKey,
	generatedOperations volumetypes.GeneratedOperations) error {
	grm.lock.Lock()
	defer grm.lock.Unlock()

	opExists, previousOpIndex := grm.isOperationExists(opKey)
	if opExists {
		previousOp := grm.operations[previousOpIndex]
		// Operation already exists
		if previousOp.operationPending {
			// Operation is pending
			return NewAlreadyExistsError(opKey)
		}

		backOffErr := previousOp.expBackoff.SafeToRetry(fmt.Sprintf("%+v", opKey))
		if backOffErr != nil {
			if previousOp.operationName == generatedOperations.OperationName {
				return backOffErr
			}
			// previous operation and new operation are different. reset op. name and exp. backoff
			grm.operations[previousOpIndex].operationName = generatedOperations.OperationName
			grm.operations[previousOpIndex].expBackoff = exponentialbackoff.ExponentialBackoff{}
		}

		// Update existing operation to mark as pending.
		grm.operations[previousOpIndex].operationPending = true
		grm.operations[previousOpIndex].key = opKey
	} else {
		// Create a new operation
		grm.operations = append(grm.operations,
			operation{
				key:              opKey,
				operationPending: true,
				operationName:    generatedOperations.OperationName,
				expBackoff:       exponentialbackoff.ExponentialBackoff{},
			})
	}

	go func() (eventErr, detailedErr error) {
		// Handle unhandled panics (very unlikely)
		defer k8sRuntime.HandleCrash()
		// Handle completion of and error, if any, from operationFunc()
		defer grm.operationComplete(opKey, &detailedErr)
		return generatedOperations.Run()
	}()

	return nil
}

func (grm *nestedPendingOperations) IsOperationPending(
	opKey volumetypes.OperationKey) bool {

	grm.lock.RLock()
	defer grm.lock.RUnlock()

	exist, previousOpIndex := grm.isOperationExists(opKey)
	if exist && grm.operations[previousOpIndex].operationPending {
		return true
	}
	return false
}

// This is an internal function and caller should acquire and release the lock
func (grm *nestedPendingOperations) isOperationExists(key volumetypes.OperationKey) (bool, int) {

	for previousOpIndex, previousOp := range grm.operations {
		if key.Matches(previousOp.key) {
			return true, previousOpIndex
		}
	}

	return false, -1
}

func (grm *nestedPendingOperations) getOperation(key volumetypes.OperationKey) (uint, error) {
	// Assumes lock has been acquired by caller.

	for i, op := range grm.operations {
		if op.key.Equals(key) {
			return uint(i), nil
		}
	}

	return 0, fmt.Errorf("Operation %+v not found", key)
}

func (grm *nestedPendingOperations) deleteOperation(key volumetypes.OperationKey) {
	// Assumes lock has been acquired by caller.

	opIndex := -1
	for i, op := range grm.operations {
		if op.key.Equals(key) {
			opIndex = i
			break
		}
	}

	if opIndex < 0 {
		return
	}

	// Delete index without preserving order
	grm.operations[opIndex] = grm.operations[len(grm.operations)-1]
	grm.operations = grm.operations[:len(grm.operations)-1]
}

func (grm *nestedPendingOperations) operationComplete(key volumetypes.OperationKey, err *error) {
	// Defer operations are executed in Last-In is First-Out order. In this case
	// the lock is acquired first when operationCompletes begins, and is
	// released when the method finishes, after the lock is released cond is
	// signaled to wake waiting goroutine.
	defer grm.cond.Signal()
	grm.lock.Lock()
	defer grm.lock.Unlock()

	if *err == nil || !grm.exponentialBackOffOnError {
		// Operation completed without error, or exponentialBackOffOnError disabled
		grm.deleteOperation(key)
		if *err != nil {
			// Log error
			klog.Errorf("operation %+v failed with: %v", key, *err)
		}
		return
	}

	// Operation completed with error and exponentialBackOffOnError Enabled
	existingOpIndex, getOpErr := grm.getOperation(key)
	if getOpErr != nil {
		// Failed to find existing operation
		klog.Errorf("Operation %+v completed. error: %v. exponentialBackOffOnError is enabled, but failed to get operation to update.",
			key,
			*err)
		return
	}

	grm.operations[existingOpIndex].expBackoff.Update(err)
	grm.operations[existingOpIndex].operationPending = false

	// Log error
	klog.Errorf("%v", grm.operations[existingOpIndex].expBackoff.
		GenerateNoRetriesPermittedMsg(fmt.Sprintf("%+v", key)))
}

func (grm *nestedPendingOperations) Wait() {
	grm.lock.Lock()
	defer grm.lock.Unlock()

	for len(grm.operations) > 0 {
		grm.cond.Wait()
	}
}

// NewAlreadyExistsError returns a new instance of AlreadyExists error.
func NewAlreadyExistsError(key volumetypes.OperationKey) error {
	return alreadyExistsError{key}
}

// IsAlreadyExists returns true if an error returned from
// NestedPendingOperations indicates a new operation can not be started because
// an operation with the same operation name is already executing.
func IsAlreadyExists(err error) bool {
	switch err.(type) {
	case alreadyExistsError:
		return true
	default:
		return false
	}
}

// alreadyExistsError is the error returned by NestedPendingOperations when a
// new operation can not be started because an operation with the same operation
// name is already executing.
type alreadyExistsError struct {
	operationKey volumetypes.OperationKey
}

var _ error = alreadyExistsError{}

func (err alreadyExistsError) Error() string {
	return fmt.Sprintf(
		"Failed to create operation with name %+v. An operation with that name is already executing.",
		err.operationKey)
}
