/*
Copyright 2014 The Kubernetes Authors.

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

package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/spf13/cobra"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest/fake"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	cmdtesting "k8s.io/kubernetes/pkg/kubectl/cmd/testing"
	"k8s.io/kubernetes/pkg/kubectl/genericclioptions"
	"k8s.io/kubernetes/pkg/kubectl/scheme"
)

type fakePortForwarder struct {
	method string
	url    *url.URL
	pfErr  error
}

func (f *fakePortForwarder) ForwardPorts(method string, url *url.URL, opts PortForwardOptions) error {
	f.method = method
	f.url = url
	return f.pfErr
}

func testPortForward(t *testing.T, flags map[string]string, args []string) {
	version := "v1"

	tests := []struct {
		name            string
		podPath, pfPath string
		pod             *v1.Pod
		pfErr           bool
	}{
		{
			name:    "pod portforward",
			podPath: "/v1/" + version + "/namespaces/test/pods/foo",
			pfPath:  "/v1/" + version + "/namespaces/test/pods/foo/portforward",
			pod:     execPod(),
		},
		{
			name:    "pod portforward error",
			podPath: "/v1/" + version + "/namespaces/test/pods/foo",
			pfPath:  "/v1/" + version + "/namespaces/test/pods/foo/portforward",
			pod:     execPod(),
			pfErr:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			tf := cmdtesting.NewTestFactory().WithNamespace("test")
			defer tf.Cleanup()

			codec := legacyscheme.Codecs.LegacyCodec(scheme.Scheme.PrioritizedVersionsAllGroups()...)
			ns := legacyscheme.Codecs

			tf.Client = &fake.RESTClient{
				VersionedAPIPath:     "/v1/v1",
				GroupVersion:         schema.GroupVersion{Group: ""},
				NegotiatedSerializer: ns,
				Client: fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
					switch p, m := req.URL.Path, req.Method; {
					case p == test.podPath && m == "GET":
						body := objBody(codec, test.pod)
						return &http.Response{StatusCode: 200, Header: defaultHeader(), Body: body}, nil
					default:
						t.Errorf("%s: unexpected request: %#v\n%#v", test.name, req.URL, req)
						return nil, nil
					}
				}),
			}
			tf.ClientConfigVal = defaultClientConfig()
			ff := &fakePortForwarder{}
			if test.pfErr {
				ff.pfErr = fmt.Errorf("pf error")
			}

			opts := &PortForwardOptions{}
			cmd := NewCmdPortForward(tf, genericclioptions.NewTestIOStreamsDiscard())
			cmd.Run = func(cmd *cobra.Command, args []string) {
				if err = opts.Complete(tf, cmd, args); err != nil {
					return
				}
				opts.PortForwarder = ff
				if err = opts.Validate(); err != nil {
					return
				}
				err = opts.RunPortForward()
			}

			for name, value := range flags {
				cmd.Flags().Set(name, value)
			}
			cmd.Run(cmd, args)

			if test.pfErr && err != ff.pfErr {
				t.Errorf("%s: Unexpected port-forward error: %v", test.name, err)
			}
			if !test.pfErr && err != nil {
				t.Errorf("%s: Unexpected error: %v", test.name, err)
			}
			if test.pfErr {
				return
			}

			if ff.url == nil || ff.url.Path != test.pfPath {
				t.Errorf("%s: Did not get expected path for portforward request", test.name)
			}
			if ff.method != "POST" {
				t.Errorf("%s: Did not get method for attach request: %s", test.name, ff.method)
			}
		})
	}
}

func TestPortForward(t *testing.T) {
	testPortForward(t, nil, []string{"foo", ":5000", ":1000"})
}

func TestTranslateServicePortToTargetPort(t *testing.T) {
	cases := []struct {
		name       string
		svc        v1.Service
		pod        v1.Pod
		ports      []string
		translated []string
		err        bool
	}{
		{
			name: "test success 1 (int port)",
			svc: v1.Service{
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
			},
			pod: v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Ports: []v1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: int32(8080)},
							},
						},
					},
				},
			},
			ports:      []string{"80"},
			translated: []string{"80:8080"},
			err:        false,
		},
		{
			name: "test success 2 (clusterIP: None)",
			svc: v1.Service{
				Spec: v1.ServiceSpec{
					ClusterIP: "None",
					Ports: []v1.ServicePort{
						{
							Port:       80,
							TargetPort: intstr.FromInt(8080),
						},
					},
				},
			},
			pod: v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Ports: []v1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: int32(8080)},
							},
						},
					},
				},
			},
			ports:      []string{"80"},
			translated: []string{"80"},
			err:        false,
		},
		{
			name: "test success 3 (named port)",
			svc: v1.Service{
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Port:       80,
							TargetPort: intstr.FromString("http"),
						},
						{
							Port:       443,
							TargetPort: intstr.FromString("https"),
						},
					},
				},
			},
			pod: v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Ports: []v1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: int32(8080)},
								{
									Name:          "https",
									ContainerPort: int32(8443)},
							},
						},
					},
				},
			},
			ports:      []string{"80", "443"},
			translated: []string{"80:8080", "443:8443"},
			err:        false,
		},
		{
			name: "test success (targetPort omitted)",
			svc: v1.Service{
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Port: 80,
						},
					},
				},
			},
			pod: v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Ports: []v1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: int32(80)},
							},
						},
					},
				},
			},
			ports:      []string{"80"},
			translated: []string{"80"},
			err:        false,
		},
		{
			name: "test failure 1 (named port lookup failure)",
			svc: v1.Service{
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Port:       80,
							TargetPort: intstr.FromString("http"),
						},
					},
				},
			},
			pod: v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Ports: []v1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: int32(443)},
							},
						},
					},
				},
			},
			ports:      []string{"80"},
			translated: []string{},
			err:        true,
		},
		{
			name: "test failure 2 (service port not declared)",
			svc: v1.Service{
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Port:       80,
							TargetPort: intstr.FromString("http"),
						},
					},
				},
			},
			pod: v1.Pod{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Ports: []v1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: int32(443)},
							},
						},
					},
				},
			},
			ports:      []string{"443"},
			translated: []string{},
			err:        true,
		},
	}

	for _, tc := range cases {
		translated, err := translateServicePortToTargetPort(tc.ports, tc.svc, tc.pod)
		if err != nil {
			if tc.err {
				continue
			}

			t.Errorf("%v: unexpected error: %v", tc.name, err)
			continue
		}

		if tc.err {
			t.Errorf("%v: unexpected success", tc.name)
			continue
		}

		if !reflect.DeepEqual(translated, tc.translated) {
			t.Errorf("%v: expected %v; got %v", tc.name, tc.translated, translated)
		}
	}
}
