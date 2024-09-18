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

	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
	examplev1 "k8s.io/code-generator/examples/crd/apis/example/v1"
	applyconfigurationexamplev1 "k8s.io/code-generator/examples/crd/applyconfiguration/example/v1"
	scheme "k8s.io/code-generator/examples/crd/clientset/versioned/scheme"
)

// ClusterTestTypesGetter has a method to return a ClusterTestTypeInterface.
// A group's client should implement this interface.
type ClusterTestTypesGetter interface {
	ClusterTestTypes() ClusterTestTypeInterface
}

// ClusterTestTypeInterface has methods to work with ClusterTestType resources.
type ClusterTestTypeInterface interface {
	Create(ctx context.Context, clusterTestType *examplev1.ClusterTestType, opts metav1.CreateOptions) (*examplev1.ClusterTestType, error)
	Update(ctx context.Context, clusterTestType *examplev1.ClusterTestType, opts metav1.UpdateOptions) (*examplev1.ClusterTestType, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, clusterTestType *examplev1.ClusterTestType, opts metav1.UpdateOptions) (*examplev1.ClusterTestType, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*examplev1.ClusterTestType, error)
	List(ctx context.Context, opts metav1.ListOptions) (*examplev1.ClusterTestTypeList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *examplev1.ClusterTestType, err error)
	Apply(ctx context.Context, clusterTestType *applyconfigurationexamplev1.ClusterTestTypeApplyConfiguration, opts metav1.ApplyOptions) (result *examplev1.ClusterTestType, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, clusterTestType *applyconfigurationexamplev1.ClusterTestTypeApplyConfiguration, opts metav1.ApplyOptions) (result *examplev1.ClusterTestType, err error)
	GetScale(ctx context.Context, clusterTestTypeName string, options metav1.GetOptions) (*autoscalingv1.Scale, error)
	UpdateScale(ctx context.Context, clusterTestTypeName string, scale *autoscalingv1.Scale, opts metav1.UpdateOptions) (*autoscalingv1.Scale, error)

	ClusterTestTypeExpansion
}

// clusterTestTypes implements ClusterTestTypeInterface
type clusterTestTypes struct {
	*gentype.ClientWithListAndApply[*examplev1.ClusterTestType, *examplev1.ClusterTestTypeList, *applyconfigurationexamplev1.ClusterTestTypeApplyConfiguration]
}

// newClusterTestTypes returns a ClusterTestTypes
func newClusterTestTypes(c *ExampleV1Client) *clusterTestTypes {
	return &clusterTestTypes{
		gentype.NewClientWithListAndApply[*examplev1.ClusterTestType, *examplev1.ClusterTestTypeList, *applyconfigurationexamplev1.ClusterTestTypeApplyConfiguration](
			"clustertesttypes",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *examplev1.ClusterTestType { return &examplev1.ClusterTestType{} },
			func() *examplev1.ClusterTestTypeList { return &examplev1.ClusterTestTypeList{} },
		),
	}
}

// GetScale takes name of the clusterTestType, and returns the corresponding autoscalingv1.Scale object, and an error if there is any.
func (c *clusterTestTypes) GetScale(ctx context.Context, clusterTestTypeName string, options metav1.GetOptions) (*autoscalingv1.Scale, error) {
	return gentype.GetSubresource[autoscalingv1.Scale](ctx, &c.Client.ResourceClient, clusterTestTypeName, "scale", options)
}

// UpdateScale takes the top resource name and the representation of a scale and updates it. Returns the server's representation of the scale, and an error, if there is any.
func (c *clusterTestTypes) UpdateScale(ctx context.Context, clusterTestTypeName string, scale *autoscalingv1.Scale, opts metav1.UpdateOptions) (*autoscalingv1.Scale, error) {
	return gentype.UpdateSubresource(ctx, c.Client, clusterTestTypeName, scale, "scale", &autoscalingv1.Scale{}, opts)
}
