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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	applyconfigurationscorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	gentype "k8s.io/client-go/gentype"
	scheme "k8s.io/client-go/kubernetes/scheme"
)

// PodsGetter has a method to return a PodInterface.
// A group's client should implement this interface.
type PodsGetter interface {
	Pods(namespace string) PodInterface
}

// PodInterface has methods to work with Pod resources.
type PodInterface interface {
	Create(ctx context.Context, pod *corev1.Pod, opts metav1.CreateOptions) (*corev1.Pod, error)
	Update(ctx context.Context, pod *corev1.Pod, opts metav1.UpdateOptions) (*corev1.Pod, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, pod *corev1.Pod, opts metav1.UpdateOptions) (*corev1.Pod, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Pod, error)
	List(ctx context.Context, opts metav1.ListOptions) (*corev1.PodList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *corev1.Pod, err error)
	Apply(ctx context.Context, pod *applyconfigurationscorev1.PodApplyConfiguration, opts metav1.ApplyOptions) (result *corev1.Pod, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, pod *applyconfigurationscorev1.PodApplyConfiguration, opts metav1.ApplyOptions) (result *corev1.Pod, err error)
	UpdateEphemeralContainers(ctx context.Context, podName string, pod *corev1.Pod, opts metav1.UpdateOptions) (*corev1.Pod, error)
	GetResize(ctx context.Context, podName string, options metav1.GetOptions) (*corev1.Resize, error)
	UpdateResize(ctx context.Context, podName string, resize *corev1.Resize, opts metav1.UpdateOptions) (*corev1.Resize, error)

	PodExpansion
}

// pods implements PodInterface
type pods struct {
	*gentype.ClientWithListAndApply[*corev1.Pod, *corev1.PodList, *applyconfigurationscorev1.PodApplyConfiguration]
}

// newPods returns a Pods
func newPods(c *CoreV1Client, namespace string) *pods {
	return &pods{
		gentype.NewClientWithListAndApply[*corev1.Pod, *corev1.PodList, *applyconfigurationscorev1.PodApplyConfiguration](
			"pods",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *corev1.Pod { return &corev1.Pod{} },
			func() *corev1.PodList { return &corev1.PodList{} }),
	}
}

// UpdateEphemeralContainers takes the top resource name and the representation of a pod and updates it. Returns the server's representation of the pod, and an error, if there is any.
func (c *pods) UpdateEphemeralContainers(ctx context.Context, podName string, pod *corev1.Pod, opts metav1.UpdateOptions) (result *corev1.Pod, err error) {
	result = &corev1.Pod{}
	err = c.GetClient().Put().
		Namespace(c.GetNamespace()).
		Resource("pods").
		Name(podName).
		SubResource("ephemeralcontainers").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(pod).
		Do(ctx).
		Into(result)
	return
}

// GetResize takes name of the pod, and returns the corresponding corev1.Resize object, and an error if there is any.
func (c *pods) GetResize(ctx context.Context, podName string, options metav1.GetOptions) (result *corev1.Resize, err error) {
	result = &corev1.Resize{}
	err = c.GetClient().Get().
		Namespace(c.GetNamespace()).
		Resource("pods").
		Name(podName).
		SubResource("resize").
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// UpdateResize takes the top resource name and the representation of a resize and updates it. Returns the server's representation of the resize, and an error, if there is any.
func (c *pods) UpdateResize(ctx context.Context, podName string, resize *corev1.Resize, opts metav1.UpdateOptions) (result *corev1.Resize, err error) {
	result = &corev1.Resize{}
	err = c.GetClient().Put().
		Namespace(c.GetNamespace()).
		Resource("pods").
		Name(podName).
		SubResource("resize").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(resize).
		Do(ctx).
		Into(result)
	return
}
