/*
Copyright 2017 The Kubernetes Authors.

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

// This file was automatically generated by lister-gen

package v1

import (
	v1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// NetworkPolicyLister helps list NetworkPolicies.
type NetworkPolicyLister interface {
	// List lists all NetworkPolicies in the indexer.
	List(selector labels.Selector) (ret []*v1.NetworkPolicy, err error)
	// ListWithOptions lists all NetworkPolicies in the indexer that matches the options.
	// Only options.Selector and options.IncludeUninitialized are respected.
	ListWithOptions(options metav1.ListOptions) (ret []*v1.NetworkPolicy, err error)
	// NetworkPolicies returns an object that can list and get NetworkPolicies.
	NetworkPolicies(namespace string) NetworkPolicyNamespaceLister
	NetworkPolicyListerExpansion
}

// networkPolicyLister implements the NetworkPolicyLister interface.
type networkPolicyLister struct {
	indexer cache.Indexer
}

// NewNetworkPolicyLister returns a new NetworkPolicyLister.
func NewNetworkPolicyLister(indexer cache.Indexer) NetworkPolicyLister {
	return &networkPolicyLister{indexer: indexer}
}

// List lists all NetworkPolicies in the indexer.
func (s *networkPolicyLister) List(selector labels.Selector) (ret []*v1.NetworkPolicy, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.NetworkPolicy))
	})
	return ret, err
}

// ListWithOptions lists all NetworkPolicies in the indexer.
// Only options.Selector and options.IncludeUninitialized are respected.
func (s *networkPolicyLister) ListWithOptions(options metav1.ListOptions) (ret []*v1.NetworkPolicy, err error) {
	err = cache.ListAllWithOptions(s.indexer, options, func(m interface{}) {
		ret = append(ret, m.(*v1.NetworkPolicy))
	})
	return ret, err
}

// NetworkPolicies returns an object that can list and get NetworkPolicies.
func (s *networkPolicyLister) NetworkPolicies(namespace string) NetworkPolicyNamespaceLister {
	return networkPolicyNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// NetworkPolicyNamespaceLister helps list and get NetworkPolicies.
type NetworkPolicyNamespaceLister interface {
	// List lists all NetworkPolicies in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1.NetworkPolicy, err error)
	// ListWithOptions lists all NetworkPolicies that matches the options
	// in the indexer for a given namespace.
	// Only options.Selector and options.IncludeUninitialized are respected.
	ListWithOptions(options metav1.ListOptions) (ret []*v1.NetworkPolicy, err error)
	// Get retrieves the NetworkPolicy from the indexer for a given namespace and name.
	Get(name string) (*v1.NetworkPolicy, error)
	NetworkPolicyNamespaceListerExpansion
}

// networkPolicyNamespaceLister implements the NetworkPolicyNamespaceLister
// interface.
type networkPolicyNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all NetworkPolicies in the indexer for a given namespace.
func (s networkPolicyNamespaceLister) List(selector labels.Selector) (ret []*v1.NetworkPolicy, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.NetworkPolicy))
	})
	return ret, err
}

// ListWithOptions lists all NetworkPolicies that matches the options
// in the indexer for a given namespace.
func (s networkPolicyNamespaceLister) ListWithOptions(options metav1.ListOptions) (ret []*v1.NetworkPolicy, err error) {
	err = cache.ListAllByNamespaceWithOptions(s.indexer, s.namespace, options, func(m interface{}) {
		ret = append(ret, m.(*v1.NetworkPolicy))
	})
	return ret, err
}

// Get retrieves the NetworkPolicy from the indexer for a given namespace and name.
func (s networkPolicyNamespaceLister) Get(name string) (*v1.NetworkPolicy, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("networkpolicy"), name)
	}
	return obj.(*v1.NetworkPolicy), nil
}
