/*
Copyright 2015 The Kubernetes Authors.

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

package configmap

import (
	"context"
	"fmt"

	"k8s.io/api/kubefeaturegates"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	pkgstorage "k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
	utilfeature "k8s.io/component-base/featuregateinstance"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/core/validation"
)

// strategy implements behavior for ConfigMap objects
type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// Strategy is the default logic that applies when creating and updating ConfigMap
// objects via the REST API.
var Strategy = strategy{legacyscheme.Scheme, names.SimpleNameGenerator}

// Strategy should implement rest.RESTCreateStrategy
var _ rest.RESTCreateStrategy = Strategy

// Strategy should implement rest.RESTUpdateStrategy
var _ rest.RESTUpdateStrategy = Strategy

func (strategy) NamespaceScoped() bool {
	return true
}

func (strategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	configMap := obj.(*api.ConfigMap)
	dropDisabledFields(configMap, nil)
}

func (strategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	cfg := obj.(*api.ConfigMap)

	return validation.ValidateConfigMap(cfg)
}

// Canonicalize normalizes the object after validation.
func (strategy) Canonicalize(obj runtime.Object) {
}

func (strategy) AllowCreateOnUpdate() bool {
	return false
}

func (strategy) PrepareForUpdate(ctx context.Context, newObj, oldObj runtime.Object) {
	oldConfigMap := oldObj.(*api.ConfigMap)
	newConfigMap := newObj.(*api.ConfigMap)
	dropDisabledFields(newConfigMap, oldConfigMap)
}

func (strategy) ValidateUpdate(ctx context.Context, newObj, oldObj runtime.Object) field.ErrorList {
	oldCfg, newCfg := oldObj.(*api.ConfigMap), newObj.(*api.ConfigMap)

	return validation.ValidateConfigMapUpdate(newCfg, oldCfg)
}

func isImmutableInUse(configMap *api.ConfigMap) bool {
	return configMap != nil && configMap.Immutable != nil
}

func dropDisabledFields(configMap *api.ConfigMap, oldConfigMap *api.ConfigMap) {
	if !utilfeature.DefaultFeatureGate.Enabled(kubefeaturegates.ImmutableEphemeralVolumes) && !isImmutableInUse(oldConfigMap) {
		configMap.Immutable = nil
	}
}

func (strategy) AllowUnconditionalUpdate() bool {
	return true
}

// GetAttrs returns labels and fields of a given object for filtering purposes.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	configMap, ok := obj.(*api.ConfigMap)
	if !ok {
		return nil, nil, fmt.Errorf("not a configmap")
	}
	return labels.Set(configMap.Labels), SelectableFields(configMap), nil
}

// Matcher returns a selection predicate for a given label and field selector.
func Matcher(label labels.Selector, field fields.Selector) pkgstorage.SelectionPredicate {
	return pkgstorage.SelectionPredicate{
		Label:       label,
		Field:       field,
		GetAttrs:    GetAttrs,
		IndexFields: []string{"metadata.name"},
	}
}

// NameTriggerFunc returns value metadata.namespace of given object.
func NameTriggerFunc(obj runtime.Object) string {
	return obj.(*api.ConfigMap).ObjectMeta.Name
}

// SelectableFields returns a field set that can be used for filter selection
func SelectableFields(obj *api.ConfigMap) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}
