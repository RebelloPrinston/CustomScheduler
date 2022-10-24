/*
Copyright 2022 The Kubernetes Authors.

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

package cel

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"k8s.io/api/admissionregistration/v1alpha1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/cel/internal/generic"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// celAdmissionController is the top-level controller for admission control using CEL
// it is responsible for watching policy definitions, bindings, and config param CRDs
type celAdmissionController struct {
	// Context under which the controller runs
	runningContext context.Context

	policyDefinitionsController generic.Controller[*v1alpha1.ValidatingAdmissionPolicy]
	policyBindingController     generic.Controller[*v1alpha1.ValidatingAdmissionPolicyBinding]

	// dynamicclient used to create informers to watch the param crd types
	dynamicClient dynamic.Interface
	restMapper    meta.RESTMapper

	// Provided to the policy's Compile function as an injected dependency to
	// assist with compiling its expressions to CEL
	objectConverter ValidatorCompiler

	// Lock which protects:
	//	- definitionInfo
	//  - bindingInfos
	//  - paramCRDControllers
	//  - definitionsToBindings
	// All other fields should be assumed constant
	mutex sync.RWMutex

	// controller and metadata
	paramsCRDControllers map[v1alpha1.ParamKind]*paramInfo

	// Index for each definition namespace/name, contains all binding
	// namespace/names known to exist for that definition
	definitionInfo map[string]*definitionInfo

	// Index for each bindings namespace/name. Contains compiled templates
	// for the binding depending on the policy/param combination.
	bindingInfos map[string]*bindingInfo

	// Map from namespace/name of a definition to a set of namespace/name
	// of bindings which depend on it.
	// All keys must have at least one dependent binding
	// All binding names MUST exist as a key bindingInfos
	definitionsToBindings map[string]sets.String
}

type definitionInfo struct {
	// Error about the state of the definition's configuration and the cluster
	// preventing its enforcement or compilation.
	// Reset every reconciliation
	configurationError error

	// Last value seen by this controller to be used in policy enforcement
	// May not be nil
	lastReconciledValue *v1alpha1.ValidatingAdmissionPolicy
}

type bindingInfo struct {
	// Compiled CEL expression turned into an validator
	validator Validator

	// Last value seen by this controller to be used in policy enforcement
	// May not be nil
	lastReconciledValue *v1alpha1.ValidatingAdmissionPolicyBinding
}

type paramInfo struct {
	// Controller which is watching this param CRD
	controller generic.Controller[*unstructured.Unstructured]

	// Function to call to stop the informer and clean up the controller
	stop func()

	// Policy Definitions which refer to this param CRD
	dependentDefinitions sets.String
}

func NewAdmissionController(
	// Informers
	policyDefinitionsInformer cache.SharedIndexInformer,
	policyBindingInformer cache.SharedIndexInformer,

	// Injected Dependencies
	objectConverter ValidatorCompiler,
	restMapper meta.RESTMapper,
	dynamicClient dynamic.Interface,
) CELPolicyEvaluator {
	c := &celAdmissionController{
		definitionInfo:        make(map[string]*definitionInfo),
		bindingInfos:          make(map[string]*bindingInfo),
		paramsCRDControllers:  make(map[v1alpha1.ParamKind]*paramInfo),
		definitionsToBindings: make(map[string]sets.String),
		dynamicClient:         dynamicClient,
		objectConverter:       objectConverter,
		restMapper:            restMapper,
	}

	c.policyDefinitionsController = generic.NewController(
		generic.NewInformer[*v1alpha1.ValidatingAdmissionPolicy](policyDefinitionsInformer),
		c.reconcilePolicyDefinition,
		generic.ControllerOptions{
			Workers: 1,
			Name:    "cel-policy-definitions",
		},
	)
	c.policyBindingController = generic.NewController(
		generic.NewInformer[*v1alpha1.ValidatingAdmissionPolicyBinding](policyBindingInformer),
		c.reconcilePolicyBinding,
		generic.ControllerOptions{
			Workers: 1,
			Name:    "cel-policy-bindings",
		},
	)
	return c
}

func (c *celAdmissionController) Run(stopCh <-chan struct{}) {
	if c.runningContext != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.runningContext = ctx
	defer func() {
		c.runningContext = nil
	}()

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.policyDefinitionsController.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.policyBindingController.Run(ctx)
	}()

	<-stopCh
	cancel()
	wg.Wait()
}

func (c *celAdmissionController) Validate(
	ctx context.Context,
	a admission.Attributes,
	o admission.ObjectInterfaces,
) (err error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var allDecisions []PolicyDecisionWithMetadata = nil

	addConfigError := func(err error, definition *v1alpha1.ValidatingAdmissionPolicy, binding *v1alpha1.ValidatingAdmissionPolicyBinding) {
		wrappedError := fmt.Errorf("configuration error: %w", err)

		// What is default?
		policy := v1alpha1.Fail
		if definition.Spec.FailurePolicy != nil {
			policy = *definition.Spec.FailurePolicy
		}

		switch policy {
		case v1alpha1.Ignore:
			klog.Info(wrappedError)
			return
		case v1alpha1.Fail:
			allDecisions = append(allDecisions, PolicyDecisionWithMetadata{
				PolicyDecision: PolicyDecision{
					Kind:    Deny,
					Message: wrappedError.Error(),
				},
				Definition: definition,
				Binding:    binding,
			})
		default:
			utilruntime.HandleError(fmt.Errorf("unrecognized failure policy: '%v'", policy))
		}
	}
	for definitionNamespacedName, definitionInfo := range c.definitionInfo {
		definition := definitionInfo.lastReconciledValue
		if !c.objectConverter.DefinitionMatches(definition, a) {
			// Policy definition does not match request
			continue
		} else if definitionInfo.configurationError != nil {
			// Configuration error.
			addConfigError(definitionInfo.configurationError, definition, nil)
			continue
		}

		dependentBindings := c.definitionsToBindings[definitionNamespacedName]
		if len(dependentBindings) == 0 {
			// Definition has no known bindings yet.
			addConfigError(errors.New("no bindings found"), definition, nil)
			continue
		}

		for namespacedBindingName := range dependentBindings {
			// If the key is inside dependentBindings, there is guaranteed to
			// be a bindingInfo for it
			bindingInfo := c.bindingInfos[namespacedBindingName]
			binding := bindingInfo.lastReconciledValue
			if !c.objectConverter.BindingMatches(binding, a) {
				continue
			}

			var param *unstructured.Unstructured

			// If definition has no paramsource, always provide nil params to
			// evaluator. If binding specifies a params to use they are ignored.
			// Done this way so you can configure params before definition is ready.
			if paramSource := definition.Spec.ParamKind; paramSource != nil {
				paramRef := binding.Spec.ParamRef
				if paramRef == nil {
					addConfigError(fmt.Errorf("paramSource kind `%v` not specified despite being required by policy definition",
						paramSource.String()), definition, binding)
					continue
				}

				// Find the params referred by the binding by looking its name up
				// in our informer for its CRD
				paramInfo, ok := c.paramsCRDControllers[*paramSource]
				if !ok {
					addConfigError(fmt.Errorf("paramSource kind `%v` not known",
						paramSource.String()), definition, binding)
					continue
				}

				if len(paramRef.Namespace) == 0 {
					param, err = paramInfo.controller.Informer().Get(paramRef.Name)
				} else {
					param, err = paramInfo.controller.Informer().Namespaced(paramRef.Namespace).Get(paramRef.Name)
				}

				if err != nil {
					// Apply failure policy
					addConfigError(err, definition, binding)

					if k8serrors.IsNotFound(err) {
						// Param doesnt exist yet?
						// Maybe just have to wait a bit.
						continue
					}

					// There was a bad internal error
					utilruntime.HandleError(err)
					continue
				}
			}

			if bindingInfo.validator == nil {
				// Compile policy definition using binding
				bindingInfo.validator, err = c.objectConverter.Compile(definition, c.restMapper)
				if err != nil {
					// compilation error. Apply failure policy
					wrappedError := fmt.Errorf("failed to compile CEL expression: %w", err)
					addConfigError(wrappedError, definition, binding)
					continue
				}
				c.bindingInfos[namespacedBindingName] = bindingInfo
			}

			decisions, err := bindingInfo.validator.Validate(a, param)
			if err != nil {
				// runtime error. Apply failure policy
				wrappedError := fmt.Errorf("failed to evaluate CEL expression: %w", err)
				addConfigError(wrappedError, definition, binding)
				continue
			}
			for _, decision := range decisions {
				switch decision.Kind {
				case Admit:
					// Do nothing
				case Deny:
					allDecisions = append(allDecisions, PolicyDecisionWithMetadata{
						Definition:     definition,
						Binding:        binding,
						PolicyDecision: decision,
					})
				default:
					// unrecognized decision. ignore
				}
			}
		}
	}

	if len(allDecisions) > 0 {
		return k8serrors.NewConflict(
			a.GetResource().GroupResource(), a.GetName(),
			&PolicyError{
				Decisions: allDecisions,
			})
	}

	return nil
}
func (c *celAdmissionController) HasSynced() bool {
	return c.policyBindingController.HasSynced() &&
		c.policyDefinitionsController.HasSynced()
}
