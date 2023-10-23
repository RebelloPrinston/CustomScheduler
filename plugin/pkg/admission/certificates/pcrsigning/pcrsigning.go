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

// Package pcrsigning is an admission plugin that checks that callers who want
// to issue a certificate to a given PodCertificateRequest have the "signing"
// verb on the signer name.
package pcrsigning

import (
	"context"
	"fmt"
	"io"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apiserver/pkg/admission"
	genericadmissioninit "k8s.io/apiserver/pkg/admission/initializer"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/component-base/featuregate"
	"k8s.io/klog/v2"
	certapi "k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/kubernetes/pkg/features"
	certadmission "k8s.io/kubernetes/plugin/pkg/admission/certificates"
)

// PluginName names the plugin.
const PluginName = "PodCertificateRequestSigning"

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(config io.Reader) (admission.Interface, error) {
		return NewPlugin(), nil
	})
}

// Plugin holds state for and implements the admission plugin.
type Plugin struct {
	*admission.Handler
	enabled               bool
	inspectedFeatureGates bool
	authz                 authorizer.Authorizer
}

var _ admission.ValidationInterface = &Plugin{}
var _ admission.InitializationValidator = &Plugin{}
var _ genericadmissioninit.WantsAuthorizer = &Plugin{}
var _ genericadmissioninit.WantsFeatures = &Plugin{}

// NewPlugin creates a new CSR approval admission plugin
func NewPlugin() *Plugin {
	return &Plugin{
		Handler: admission.NewHandler(admission.Update),
	}
}

// SetAuthorizer sets the authorizer.
func (p *Plugin) SetAuthorizer(authz authorizer.Authorizer) {
	p.authz = authz
}

// InspectFeatureGates implements WantsFeatures.
func (p *Plugin) InspectFeatureGates(featureGates featuregate.FeatureGate) {
	p.enabled = featureGates.Enabled(features.PodCertificateRequest)
	p.inspectedFeatureGates = true
}

// ValidateInitialization ensures an authorizer is set.
func (p *Plugin) ValidateInitialization() error {
	if p.authz == nil {
		return fmt.Errorf("%s requires an authorizer", PluginName)
	}
	if !p.inspectedFeatureGates {
		return fmt.Errorf("%s did not see feature gates", PluginName)
	}
	return nil
}

var pcrGroupResource = certapi.Resource("podcertificaterequests")

// Validate verifies that the requesting user has permission to sign
// PodCertificateRequests for the specified signerName.
func (p *Plugin) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	if !p.enabled {
		return nil
	}

	// Ignore all calls to anything other than 'podcertificaterequests/status'.
	// Ignore all operations other than UPDATE.
	if a.GetSubresource() != "status" ||
		a.GetResource().GroupResource() != pcrGroupResource {
		return nil
	}

	oldPCR, ok := a.GetOldObject().(*certapi.PodCertificateRequest)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type PodCertificateRequest, got: %T", a.GetOldObject()))
	}
	pcr, ok := a.GetObject().(*certapi.PodCertificateRequest)
	if !ok {
		return admission.NewForbidden(a, fmt.Errorf("expected type PodCertificateRequest, got: %T", a.GetObject()))
	}

	// only run if the status.certificate or status.conditions field has been changed
	if oldPCR.Status.CertificateChain == pcr.Status.CertificateChain && apiequality.Semantic.DeepEqual(oldPCR.Status.Conditions, pcr.Status.Conditions) {
		return nil
	}

	if !certadmission.IsAuthorizedForSignerName(ctx, p.authz, a.GetUserInfo(), "sign", oldPCR.Spec.SignerName) {
		klog.V(4).Infof("user not permitted to sign PodCertificateRequest %q with signerName %q", oldPCR.Name, oldPCR.Spec.SignerName)
		return admission.NewForbidden(a, fmt.Errorf("user not permitted to sign requests with signerName %q", oldPCR.Spec.SignerName))
	}

	return nil
}
