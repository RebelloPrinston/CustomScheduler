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

// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	context "context"
	time "time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
	consistencydetector "k8s.io/client-go/util/consistencydetector"
	watchlist "k8s.io/client-go/util/watchlist"
	extensionsv1 "k8s.io/code-generator/examples/crd/apis/extensions/v1"
	applyconfigurationextensionsv1 "k8s.io/code-generator/examples/crd/applyconfiguration/extensions/v1"
	scheme "k8s.io/code-generator/examples/crd/clientset/versioned/scheme"
	v2 "k8s.io/klog/v2"
)

// TestTypesGetter has a method to return a TestTypeInterface.
// A group's client should implement this interface.
type TestTypesGetter interface {
	TestTypes(namespace string) TestTypeInterface
}

// TestTypeInterface has methods to work with TestType resources.
type TestTypeInterface interface {
	Create(ctx context.Context, testType *extensionsv1.TestType, opts metav1.CreateOptions) (*extensionsv1.TestType, error)
	Update(ctx context.Context, testType *extensionsv1.TestType, opts metav1.UpdateOptions) (*extensionsv1.TestType, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, testType *extensionsv1.TestType, opts metav1.UpdateOptions) (*extensionsv1.TestType, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*extensionsv1.TestType, error)
	List(ctx context.Context, opts metav1.ListOptions) (*extensionsv1.TestTypeList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *extensionsv1.TestType, err error)
	Apply(ctx context.Context, testType *applyconfigurationextensionsv1.TestTypeApplyConfiguration, opts metav1.ApplyOptions) (result *extensionsv1.TestType, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, testType *applyconfigurationextensionsv1.TestTypeApplyConfiguration, opts metav1.ApplyOptions) (result *extensionsv1.TestType, err error)
	GetExtended(ctx context.Context, name string, opts metav1.GetOptions) (*extensionsv1.TestType, error)
	ListExtended(ctx context.Context, opts metav1.ListOptions) (*extensionsv1.TestTypeList, error)
	CreateExtended(ctx context.Context, testType *extensionsv1.TestType, opts metav1.CreateOptions) (*extensionsv1.TestType, error)
	UpdateExtended(ctx context.Context, testType *extensionsv1.TestType, opts metav1.UpdateOptions) (*extensionsv1.TestType, error)
	PatchExtended(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *extensionsv1.TestType, err error)
	ApplyExtended(ctx context.Context, testType *applyconfigurationextensionsv1.TestTypeApplyConfiguration, opts metav1.ApplyOptions) (result *extensionsv1.TestType, err error)
	GetSubresource(ctx context.Context, testTypeName string, options metav1.GetOptions) (*extensionsv1.TestSubresource, error)
	CreateSubresource(ctx context.Context, testTypeName string, testSubresource *extensionsv1.TestSubresource, opts metav1.CreateOptions) (*extensionsv1.TestSubresource, error)
	UpdateSubresource(ctx context.Context, testTypeName string, testSubresource *extensionsv1.TestSubresource, opts metav1.UpdateOptions) (*extensionsv1.TestSubresource, error)
	ApplySubresource(ctx context.Context, testTypeName string, testSubresource *applyconfigurationextensionsv1.TestSubresourceApplyConfiguration, opts metav1.ApplyOptions) (*extensionsv1.TestSubresource, error)

	TestTypeExpansion
}

// testTypes implements TestTypeInterface
type testTypes struct {
	*gentype.ClientWithListAndApply[*extensionsv1.TestType, *extensionsv1.TestTypeList, *applyconfigurationextensionsv1.TestTypeApplyConfiguration]
}

// newTestTypes returns a TestTypes
func newTestTypes(c *ExtensionsExampleV1Client, namespace string) *testTypes {
	return &testTypes{
		gentype.NewClientWithListAndApply[*extensionsv1.TestType, *extensionsv1.TestTypeList, *applyconfigurationextensionsv1.TestTypeApplyConfiguration](
			"testtypes",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *extensionsv1.TestType { return &extensionsv1.TestType{} },
			func() *extensionsv1.TestTypeList { return &extensionsv1.TestTypeList{} },
		),
	}
}

// GetExtended takes name of the testType, and returns the corresponding testType object, and an error if there is any.
func (c *testTypes) GetExtended(ctx context.Context, name string, options metav1.GetOptions) (*extensionsv1.TestType, error) {
	return gentype.Get[extensionsv1.TestType](ctx, &c.Client.ResourceClient, name, options)
}

// ListExtended takes label and field selectors, and returns the list of TestTypes that match those selectors.
func (c *testTypes) ListExtended(ctx context.Context, opts metav1.ListOptions) (*extensionsv1.TestTypeList, error) {
	if watchListOptions, hasWatchListOptionsPrepared, watchListOptionsErr := watchlist.PrepareWatchListOptionsFromListOptions(opts); watchListOptionsErr != nil {
		v2.Warningf("Failed preparing watchlist options for testtypes, falling back to the standard LIST semantics, err = %v", watchListOptionsErr)
	} else if hasWatchListOptionsPrepared {
		result, err := c.watchList(ctx, watchListOptions)
		if err == nil {
			consistencydetector.CheckWatchListFromCacheDataConsistencyIfRequested(ctx, "watchlist request for testtypes", c.list, opts, result)
			return result, nil
		}
		v2.Warningf("The watchlist request for testtypes ended with an error, falling back to the standard LIST semantics, err = %v", err)
	}
	result, err := c.list(ctx, opts)
	if err == nil {
		consistencydetector.CheckListFromCacheDataConsistencyIfRequested(ctx, "list request for testtypes", c.list, opts, result)
	}
	return result, err
}

// list takes label and field selectors, and returns the list of TestTypes that match those selectors.
func (c *testTypes) list(ctx context.Context, opts metav1.ListOptions) (result *extensionsv1.TestTypeList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &extensionsv1.TestTypeList{}
	err = c.GetClient().Get().
		Namespace(c.GetNamespace()).
		Resource("testtypes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// watchList establishes a watch stream with the server and returns the list of TestTypes
func (c *testTypes) watchList(ctx context.Context, opts metav1.ListOptions) (result *extensionsv1.TestTypeList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &extensionsv1.TestTypeList{}
	err = c.GetClient().Get().
		Namespace(c.GetNamespace()).
		Resource("testtypes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		WatchList(ctx).
		Into(result)
	return
}

// CreateExtended takes the representation of a testType and creates it.  Returns the server's representation of the testType, and an error, if there is any.
func (c *testTypes) CreateExtended(ctx context.Context, testType *extensionsv1.TestType, opts metav1.CreateOptions) (*extensionsv1.TestType, error) {
	return gentype.Create(ctx, c.Client, &extensionsv1.TestType{}, testType, opts)
}

// UpdateExtended takes the representation of a testType and updates it. Returns the server's representation of the testType, and an error, if there is any.
func (c *testTypes) UpdateExtended(ctx context.Context, testType *extensionsv1.TestType, opts metav1.UpdateOptions) (*extensionsv1.TestType, error) {
	return gentype.Update(ctx, c.Client, testType, &extensionsv1.TestType{}, opts)
}

// PatchExtended applies the patch and returns the patched testType.
func (c *testTypes) PatchExtended(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (*extensionsv1.TestType, error) {
	return gentype.Patch(ctx, c.Client, name, pt, data, &extensionsv1.TestType{}, opts, subresources...)
}

// ApplyExtended takes the given apply declarative configuration, applies it and returns the applied testType.
func (c *testTypes) ApplyExtended(ctx context.Context, testType *applyconfigurationextensionsv1.TestTypeApplyConfiguration, opts metav1.ApplyOptions) (result *extensionsv1.TestType, err error) {
	return gentype.Apply(ctx, c.Client, testType, &extensionsv1.TestType{}, opts)
}

// GetSubresource takes name of the testType, and returns the corresponding extensionsv1.TestSubresource object, and an error if there is any.
func (c *testTypes) GetSubresource(ctx context.Context, testTypeName string, options metav1.GetOptions) (*extensionsv1.TestSubresource, error) {
	return gentype.GetSubresource[extensionsv1.TestSubresource](ctx, &c.Client.ResourceClient, testTypeName, "testsubresource", options)
}

// CreateSubresource takes the representation of a testSubresource and creates it.  Returns the server's representation of the testSubresource, and an error, if there is any.
func (c *testTypes) CreateSubresource(ctx context.Context, testTypeName string, testSubresource *extensionsv1.TestSubresource, opts metav1.CreateOptions) (*extensionsv1.TestSubresource, error) {
	return gentype.CreateSubresource(ctx, c.Client, testTypeName, testSubresource, "testsubresource", &extensionsv1.TestSubresource{}, opts)
}

// UpdateSubresource takes the top resource name and the representation of a testSubresource and updates it. Returns the server's representation of the testSubresource, and an error, if there is any.
func (c *testTypes) UpdateSubresource(ctx context.Context, testTypeName string, testSubresource *extensionsv1.TestSubresource, opts metav1.UpdateOptions) (*extensionsv1.TestSubresource, error) {
	return gentype.UpdateSubresource(ctx, c.Client, testTypeName, testSubresource, "subresource", &extensionsv1.TestSubresource{}, opts)
}

// ApplySubresource takes top resource name and the apply declarative configuration for subresource,
// applies it and returns the applied testSubresource, and an error, if there is any.
func (c *testTypes) ApplySubresource(ctx context.Context, testTypeName string, testSubresource *applyconfigurationextensionsv1.TestSubresourceApplyConfiguration, opts metav1.ApplyOptions) (result *extensionsv1.TestSubresource, err error) {
	return gentype.ApplySubresource(ctx, c.Client, testTypeName, testSubresource, "subresource", &extensionsv1.TestSubresource{}, opts)
}
