/*
Copyright 2024 The Kubernetes Authors.

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

package pcrsigning

import (
	"context"
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	certificatesapi "k8s.io/kubernetes/pkg/apis/certificates"
)

func TestPlugin_Validate(t *testing.T) {
	tests := map[string]struct {
		pluginEnabled bool
		attributes    admission.Attributes
		allowedName   string
		allowed       bool
		authzErr      error
	}{
		"wrong type, plugin disabled": {
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj:      &certificatesapi.PodCertificateRequestList{},
				obj:         &certificatesapi.PodCertificateRequestList{},
				operation:   admission.Update,
			},
			allowed: true,
		},
		"wrong type": {
			pluginEnabled: true,
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj:      &certificatesapi.PodCertificateRequestList{},
				obj:         &certificatesapi.PodCertificateRequestList{},
				operation:   admission.Update,
			},
			allowed: false,
		},
		"allowed if the 'certificate' and conditions field has not changed": {
			pluginEnabled: true,
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj: &certificatesapi.PodCertificateRequest{Status: certificatesapi.PodCertificateRequestStatus{
					CertificateChain: "data",
				}},
				obj: &certificatesapi.PodCertificateRequest{Status: certificatesapi.PodCertificateRequestStatus{
					CertificateChain: "data",
				}},
				operation: admission.Update,
			},
			allowed:  true,
			authzErr: errors.New("faked error"),
		},
		"deny request if authz lookup fails on certificate change": {
			pluginEnabled: true,
			allowedName:   "abc.com/xyz",
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj: &certificatesapi.PodCertificateRequest{Spec: certificatesapi.PodCertificateRequestSpec{
					SignerName: "abc.com/xyz",
				}},
				obj: &certificatesapi.PodCertificateRequest{
					Spec: certificatesapi.PodCertificateRequestSpec{
						SignerName: "abc.com/xyz",
					},
					Status: certificatesapi.PodCertificateRequestStatus{
						CertificateChain: "data",
					},
				},
				operation: admission.Update,
			},
			authzErr: errors.New("test"),
			allowed:  false,
		},
		"deny request if authz lookup fails on condition change": {
			pluginEnabled: true,
			allowedName:   "abc.com/xyz",
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj: &certificatesapi.PodCertificateRequest{
					Spec: certificatesapi.PodCertificateRequestSpec{
						SignerName: "abc.com/xyz",
					},
				},
				obj: &certificatesapi.PodCertificateRequest{
					Spec: certificatesapi.PodCertificateRequestSpec{
						SignerName: "abc.com/xyz",
					},
					Status: certificatesapi.PodCertificateRequestStatus{
						Conditions: []metav1.Condition{
							{
								Type: string(certificatesapi.CertificateFailed),
							},
						},
					},
				},
				operation: admission.Update,
			},
			authzErr: errors.New("test"),
			allowed:  false,
		},
		"allow request if user is authorized for specific signerName": {
			pluginEnabled: true,
			allowedName:   "abc.com/xyz",
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj: &certificatesapi.PodCertificateRequest{Spec: certificatesapi.PodCertificateRequestSpec{
					SignerName: "abc.com/xyz",
				}},
				obj: &certificatesapi.PodCertificateRequest{
					Spec: certificatesapi.PodCertificateRequestSpec{
						SignerName: "abc.com/xyz",
					},
					Status: certificatesapi.PodCertificateRequestStatus{
						CertificateChain: "data",
					},
				},
				operation: admission.Update,
			},
			allowed: true,
		},
		"allow request if user is authorized with wildcard": {
			pluginEnabled: true,
			allowedName:   "abc.com/*",
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj: &certificatesapi.PodCertificateRequest{Spec: certificatesapi.PodCertificateRequestSpec{
					SignerName: "abc.com/xyz",
				}},
				obj: &certificatesapi.PodCertificateRequest{
					Spec: certificatesapi.PodCertificateRequestSpec{
						SignerName: "abc.com/xyz",
					},
					Status: certificatesapi.PodCertificateRequestStatus{
						CertificateChain: "data",
					},
				},
				operation: admission.Update,
			},
			allowed: true,
		},
		"should deny request if user does not have permission for this signerName": {
			pluginEnabled: true,
			allowedName:   "notabc.com/xyz",
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj: &certificatesapi.PodCertificateRequest{Spec: certificatesapi.PodCertificateRequestSpec{
					SignerName: "abc.com/xyz",
				}},
				obj: &certificatesapi.PodCertificateRequest{
					Spec: certificatesapi.PodCertificateRequestSpec{
						SignerName: "abc.com/xyz",
					},
					Status: certificatesapi.PodCertificateRequestStatus{
						CertificateChain: "data",
					},
				},
				operation: admission.Update,
			},
			allowed: false,
		},
		"should deny request if user attempts to update signerName to a new value they *do* have permission to sign for": {
			pluginEnabled: true,
			allowedName:   "allowed.com/xyz",
			attributes: &testAttributes{
				resource:    certificatesapi.Resource("podcertificaterequests"),
				subresource: "status",
				oldObj: &certificatesapi.PodCertificateRequest{Spec: certificatesapi.PodCertificateRequestSpec{
					SignerName: "notallowed.com/xyz",
				}},
				obj: &certificatesapi.PodCertificateRequest{
					Spec: certificatesapi.PodCertificateRequestSpec{
						SignerName: "allowed.com/xyz",
					},
					Status: certificatesapi.PodCertificateRequestStatus{
						CertificateChain: "data",
					},
				},
				operation: admission.Update,
			},
			allowed: false,
		},
	}
	for n, test := range tests {
		t.Run(n, func(t *testing.T) {
			p := Plugin{
				authz: fakeAuthorizer{
					t:           t,
					verb:        "sign",
					allowedName: test.allowedName,
					decision:    authorizer.DecisionAllow,
					err:         test.authzErr,
				},
				enabled:               test.pluginEnabled,
				inspectedFeatureGates: true,
			}
			err := p.Validate(context.Background(), test.attributes, nil)
			if err == nil && !test.allowed {
				t.Errorf("Expected authorization policy to reject PCR but it was allowed")
			}
			if err != nil && test.allowed {
				t.Errorf("Expected authorization policy to accept PCR but it was rejected: %v", err)
			}
		})
	}
}

type fakeAuthorizer struct {
	t           *testing.T
	verb        string
	allowedName string
	decision    authorizer.Decision
	err         error
}

func (f fakeAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	if f.err != nil {
		return f.decision, "forced error", f.err
	}
	if a.GetVerb() != f.verb {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised verb '%s'", a.GetVerb()), nil
	}
	if a.GetAPIGroup() != "certificates.k8s.io" {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised groupName '%s'", a.GetAPIGroup()), nil
	}
	if a.GetAPIVersion() != "*" {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised apiVersion '%s'", a.GetAPIVersion()), nil
	}
	if a.GetResource() != "signers" {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised resource '%s'", a.GetResource()), nil
	}
	if a.GetName() != f.allowedName {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised resource name '%s'", a.GetName()), nil
	}
	if !a.IsResourceRequest() {
		return authorizer.DecisionDeny, fmt.Sprintf("unrecognised IsResourceRequest '%t'", a.IsResourceRequest()), nil
	}
	return f.decision, "", nil
}

type testAttributes struct {
	resource    schema.GroupResource
	subresource string
	operation   admission.Operation
	oldObj, obj runtime.Object
	name        string

	admission.Attributes // nil panic if any other methods called
}

func (t *testAttributes) GetResource() schema.GroupVersionResource {
	return t.resource.WithVersion("ignored")
}

func (t *testAttributes) GetSubresource() string {
	return t.subresource
}

func (t *testAttributes) GetOldObject() runtime.Object {
	return t.oldObj
}

func (t *testAttributes) GetObject() runtime.Object {
	return t.obj
}

func (t *testAttributes) GetName() string {
	return t.name
}

func (t *testAttributes) GetOperation() admission.Operation {
	return t.operation
}

func (t *testAttributes) GetUserInfo() user.Info {
	return &user.DefaultInfo{Name: "ignored"}
}
