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

package validation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	utilcert "k8s.io/client-go/util/cert"
	"k8s.io/kubernetes/pkg/apis/certificates"
	apivalidation "k8s.io/kubernetes/pkg/apis/core/validation"
)

var (
	// trueConditionTypes is the set of condition types which may only have a status of True if present
	trueConditionTypes = sets.NewString(
		string(certificates.CertificateApproved),
		string(certificates.CertificateDenied),
		string(certificates.CertificateFailed),
	)

	trueStatusOnly  = sets.NewString(string(v1.ConditionTrue))
	allStatusValues = sets.NewString(string(v1.ConditionTrue), string(v1.ConditionFalse), string(v1.ConditionUnknown))
)

type certificateValidationOptions struct {
	// The following allow modifications only permitted via certain update paths

	// allow populating/modifying Approved/Denied conditions
	allowSettingApprovalConditions bool
	// allow populating status.certificate
	allowSettingCertificate bool

	// allow Approved and Denied conditions to be exist.
	// we tolerate this when the problem is already present in the persisted object for compatibility.
	allowBothApprovedAndDenied bool

	// The following are bad things we tolerate for compatibility reasons:
	// * in requests made via the v1beta1 API
	// * in update requests where the problem is already present in the persisted object

	// allow modifying status.certificate on an update where the old object has a different certificate
	allowResettingCertificate bool
	// allow the legacy-unknown signerName
	allowLegacySignerName bool
	// allow conditions with duplicate types
	allowDuplicateConditionTypes bool
	// allow conditions with "" types
	allowEmptyConditionType bool
	// allow arbitrary content in status.certificate
	allowArbitraryCertificate bool
	// allow usages values outside the known set
	allowUnknownUsages bool
	// allow duplicate usages values
	allowDuplicateUsages bool
}

// validateCSR validates the signature and formatting of a base64-wrapped,
// PEM-encoded PKCS#10 certificate signing request. If this is invalid, we must
// not accept the CSR for further processing.
func validateCSR(obj *certificates.CertificateSigningRequest) error {
	csr, err := certificates.ParseCSR(obj.Spec.Request)
	if err != nil {
		return err
	}
	// check that the signature is valid
	return csr.CheckSignature()
}

func validateCertificate(pemData []byte) error {
	if len(pemData) == 0 {
		return nil
	}

	blocks := 0
	for {
		block, remainingData := pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type != utilcert.CertificateBlockType {
			return fmt.Errorf("only CERTIFICATE PEM blocks are allowed, found %q", block.Type)
		}
		if len(block.Headers) != 0 {
			return fmt.Errorf("no PEM block headers are permitted")
		}
		blocks++

		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("found CERTIFICATE PEM block containing 0 certificates")
		}

		pemData = remainingData
	}

	if blocks == 0 {
		return fmt.Errorf("must contain at least one CERTIFICATE PEM block")
	}

	return nil
}

// We don't care what you call your certificate requests.
func ValidateCertificateRequestName(name string, prefix bool) []string {
	return nil
}

func ValidateCertificateSigningRequestCreate(csr *certificates.CertificateSigningRequest) field.ErrorList {
	opts := getValidationOptions(csr, nil)
	return validateCertificateSigningRequest(csr, opts)
}

var (
	allValidUsages = sets.NewString(
		string(certificates.UsageSigning),
		string(certificates.UsageDigitalSignature),
		string(certificates.UsageContentCommitment),
		string(certificates.UsageKeyEncipherment),
		string(certificates.UsageKeyAgreement),
		string(certificates.UsageDataEncipherment),
		string(certificates.UsageCertSign),
		string(certificates.UsageCRLSign),
		string(certificates.UsageEncipherOnly),
		string(certificates.UsageDecipherOnly),
		string(certificates.UsageAny),
		string(certificates.UsageServerAuth),
		string(certificates.UsageClientAuth),
		string(certificates.UsageCodeSigning),
		string(certificates.UsageEmailProtection),
		string(certificates.UsageSMIME),
		string(certificates.UsageIPsecEndSystem),
		string(certificates.UsageIPsecTunnel),
		string(certificates.UsageIPsecUser),
		string(certificates.UsageTimestamping),
		string(certificates.UsageOCSPSigning),
		string(certificates.UsageMicrosoftSGC),
		string(certificates.UsageNetscapeSGC),
	)
)

func validateCertificateSigningRequest(csr *certificates.CertificateSigningRequest, opts certificateValidationOptions) field.ErrorList {
	isNamespaced := false
	allErrs := apivalidation.ValidateObjectMeta(&csr.ObjectMeta, isNamespaced, ValidateCertificateRequestName, field.NewPath("metadata"))

	specPath := field.NewPath("spec")
	err := validateCSR(csr)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(specPath.Child("request"), csr.Spec.Request, fmt.Sprintf("%v", err)))
	}
	if len(csr.Spec.Usages) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("usages"), ""))
	}
	if !opts.allowUnknownUsages {
		for i, usage := range csr.Spec.Usages {
			if !allValidUsages.Has(string(usage)) {
				allErrs = append(allErrs, field.NotSupported(specPath.Child("usages").Index(i), usage, allValidUsages.List()))
			}
		}
	}
	if !opts.allowDuplicateUsages {
		seen := make(map[certificates.KeyUsage]bool, len(csr.Spec.Usages))
		for i, usage := range csr.Spec.Usages {
			if seen[usage] {
				allErrs = append(allErrs, field.Duplicate(specPath.Child("usages").Index(i), usage))
			}
			seen[usage] = true
		}
	}
	if !opts.allowLegacySignerName && csr.Spec.SignerName == certificates.LegacyUnknownSignerName {
		allErrs = append(allErrs, field.Invalid(specPath.Child("signerName"), csr.Spec.SignerName, "the legacy signerName is not allowed via this API version"))
	} else {
		allErrs = append(allErrs, apivalidation.ValidateSignerName(specPath.Child("signerName"), csr.Spec.SignerName)...)
	}
	if csr.Spec.ExpirationSeconds != nil && *csr.Spec.ExpirationSeconds < 600 {
		allErrs = append(allErrs, field.Invalid(specPath.Child("expirationSeconds"), *csr.Spec.ExpirationSeconds, "may not specify a duration less than 600 seconds (10 minutes)"))
	}
	allErrs = append(allErrs, validateConditions(field.NewPath("status", "conditions"), csr, opts)...)

	if !opts.allowArbitraryCertificate {
		if err := validateCertificate(csr.Status.Certificate); err != nil {
			allErrs = append(allErrs, field.Invalid(field.NewPath("status", "certificate"), "<certificate data>", err.Error()))
		}
	}

	return allErrs
}

func validateConditions(fldPath *field.Path, csr *certificates.CertificateSigningRequest, opts certificateValidationOptions) field.ErrorList {
	allErrs := field.ErrorList{}

	seenTypes := map[certificates.RequestConditionType]bool{}
	hasApproved := false
	hasDenied := false

	for i, c := range csr.Status.Conditions {

		if !opts.allowEmptyConditionType {
			if len(c.Type) == 0 {
				allErrs = append(allErrs, field.Required(fldPath.Index(i).Child("type"), ""))
			}
		}

		allowedStatusValues := allStatusValues
		if trueConditionTypes.Has(string(c.Type)) {
			allowedStatusValues = trueStatusOnly
		}
		switch {
		case c.Status == "":
			allErrs = append(allErrs, field.Required(fldPath.Index(i).Child("status"), ""))
		case !allowedStatusValues.Has(string(c.Status)):
			allErrs = append(allErrs, field.NotSupported(fldPath.Index(i).Child("status"), c.Status, allowedStatusValues.List()))
		}

		if !opts.allowBothApprovedAndDenied {
			switch c.Type {
			case certificates.CertificateApproved:
				hasApproved = true
				if hasDenied {
					allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("type"), c.Type, "Approved and Denied conditions are mutually exclusive"))
				}
			case certificates.CertificateDenied:
				hasDenied = true
				if hasApproved {
					allErrs = append(allErrs, field.Invalid(fldPath.Index(i).Child("type"), c.Type, "Approved and Denied conditions are mutually exclusive"))
				}
			}
		}

		if !opts.allowDuplicateConditionTypes {
			if seenTypes[c.Type] {
				allErrs = append(allErrs, field.Duplicate(fldPath.Index(i).Child("type"), c.Type))
			}
			seenTypes[c.Type] = true
		}
	}

	return allErrs
}

func ValidateCertificateSigningRequestUpdate(newCSR, oldCSR *certificates.CertificateSigningRequest) field.ErrorList {
	opts := getValidationOptions(newCSR, oldCSR)
	return validateCertificateSigningRequestUpdate(newCSR, oldCSR, opts)
}

func ValidateCertificateSigningRequestStatusUpdate(newCSR, oldCSR *certificates.CertificateSigningRequest) field.ErrorList {
	opts := getValidationOptions(newCSR, oldCSR)
	opts.allowSettingCertificate = true
	return validateCertificateSigningRequestUpdate(newCSR, oldCSR, opts)
}

func ValidateCertificateSigningRequestApprovalUpdate(newCSR, oldCSR *certificates.CertificateSigningRequest) field.ErrorList {
	opts := getValidationOptions(newCSR, oldCSR)
	opts.allowSettingApprovalConditions = true
	return validateCertificateSigningRequestUpdate(newCSR, oldCSR, opts)
}

func validateCertificateSigningRequestUpdate(newCSR, oldCSR *certificates.CertificateSigningRequest, opts certificateValidationOptions) field.ErrorList {
	validationErrorList := validateCertificateSigningRequest(newCSR, opts)
	metaUpdateErrorList := apivalidation.ValidateObjectMetaUpdate(&newCSR.ObjectMeta, &oldCSR.ObjectMeta, field.NewPath("metadata"))

	// prevent removal of existing Approved/Denied/Failed conditions
	for _, t := range []certificates.RequestConditionType{certificates.CertificateApproved, certificates.CertificateDenied, certificates.CertificateFailed} {
		oldConditions := findConditions(oldCSR, t)
		newConditions := findConditions(newCSR, t)
		if len(newConditions) < len(oldConditions) {
			validationErrorList = append(validationErrorList, field.Forbidden(field.NewPath("status", "conditions"), fmt.Sprintf("updates may not remove a condition of type %q", t)))
		}
	}

	if !opts.allowSettingApprovalConditions {
		// prevent addition/removal/modification of Approved/Denied conditions
		for _, t := range []certificates.RequestConditionType{certificates.CertificateApproved, certificates.CertificateDenied} {
			oldConditions := findConditions(oldCSR, t)
			newConditions := findConditions(newCSR, t)
			switch {
			case len(newConditions) < len(oldConditions):
				// removals are prevented above
			case len(newConditions) > len(oldConditions):
				validationErrorList = append(validationErrorList, field.Forbidden(field.NewPath("status", "conditions"), fmt.Sprintf("updates may not add a condition of type %q", t)))
			case !apiequality.Semantic.DeepEqual(oldConditions, newConditions):
				conditionDiff := cmp.Diff(oldConditions, newConditions)
				validationErrorList = append(validationErrorList, field.Forbidden(field.NewPath("status", "conditions"), fmt.Sprintf("updates may not modify a condition of type %q\n%v", t, conditionDiff)))
			}
		}
	}

	if !bytes.Equal(newCSR.Status.Certificate, oldCSR.Status.Certificate) {
		if !opts.allowSettingCertificate {
			validationErrorList = append(validationErrorList, field.Forbidden(field.NewPath("status", "certificate"), "updates may not set certificate content"))
		} else if !opts.allowResettingCertificate && len(oldCSR.Status.Certificate) > 0 {
			validationErrorList = append(validationErrorList, field.Forbidden(field.NewPath("status", "certificate"), "updates may not modify existing certificate content"))
		}
	}

	return append(validationErrorList, metaUpdateErrorList...)
}

// findConditions returns all instances of conditions of the specified type
func findConditions(csr *certificates.CertificateSigningRequest, conditionType certificates.RequestConditionType) []certificates.CertificateSigningRequestCondition {
	var retval []certificates.CertificateSigningRequestCondition
	for i, c := range csr.Status.Conditions {
		if c.Type == conditionType {
			retval = append(retval, csr.Status.Conditions[i])
		}
	}
	return retval
}

// getValidationOptions returns the validation options to be
// compatible with the specified version and existing CSR.
// oldCSR may be nil if this is a create request.
// validation options related to subresource-specific capabilities are set to false.
func getValidationOptions(newCSR, oldCSR *certificates.CertificateSigningRequest) certificateValidationOptions {
	return certificateValidationOptions{
		allowResettingCertificate:    false,
		allowBothApprovedAndDenied:   allowBothApprovedAndDenied(oldCSR),
		allowLegacySignerName:        allowLegacySignerName(oldCSR),
		allowDuplicateConditionTypes: allowDuplicateConditionTypes(oldCSR),
		allowEmptyConditionType:      allowEmptyConditionType(oldCSR),
		allowArbitraryCertificate:    allowArbitraryCertificate(newCSR, oldCSR),
		allowDuplicateUsages:         allowDuplicateUsages(oldCSR),
		allowUnknownUsages:           allowUnknownUsages(oldCSR),
	}
}

func allowBothApprovedAndDenied(oldCSR *certificates.CertificateSigningRequest) bool {
	if oldCSR == nil {
		return false
	}
	approved := false
	denied := false
	for _, c := range oldCSR.Status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		} else if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	// compatibility with existing data
	return approved && denied
}

func allowLegacySignerName(oldCSR *certificates.CertificateSigningRequest) bool {
	switch {
	case oldCSR != nil && oldCSR.Spec.SignerName == certificates.LegacyUnknownSignerName:
		return true // compatibility with existing data
	default:
		return false
	}
}

func allowDuplicateConditionTypes(oldCSR *certificates.CertificateSigningRequest) bool {
	switch {
	case oldCSR != nil && hasDuplicateConditionTypes(oldCSR):
		return true // compatibility with existing data
	default:
		return false
	}
}
func hasDuplicateConditionTypes(csr *certificates.CertificateSigningRequest) bool {
	seen := map[certificates.RequestConditionType]bool{}
	for _, c := range csr.Status.Conditions {
		if seen[c.Type] {
			return true
		}
		seen[c.Type] = true
	}
	return false
}

func allowEmptyConditionType(oldCSR *certificates.CertificateSigningRequest) bool {
	switch {
	case oldCSR != nil && hasEmptyConditionType(oldCSR):
		return true // compatibility with existing data
	default:
		return false
	}
}
func hasEmptyConditionType(csr *certificates.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if len(c.Type) == 0 {
			return true
		}
	}
	return false
}

func allowArbitraryCertificate(newCSR, oldCSR *certificates.CertificateSigningRequest) bool {
	switch {
	case newCSR != nil && oldCSR != nil && bytes.Equal(newCSR.Status.Certificate, oldCSR.Status.Certificate):
		return true // tolerate updates that don't touch status.certificate
	case oldCSR != nil && validateCertificate(oldCSR.Status.Certificate) != nil:
		return true // compatibility with existing data
	default:
		return false
	}
}

func allowUnknownUsages(oldCSR *certificates.CertificateSigningRequest) bool {
	switch {
	case oldCSR != nil && hasUnknownUsage(oldCSR.Spec.Usages):
		return true // compatibility with existing data
	default:
		return false
	}
}

func hasUnknownUsage(usages []certificates.KeyUsage) bool {
	for _, usage := range usages {
		if !allValidUsages.Has(string(usage)) {
			return true
		}
	}
	return false
}

func allowDuplicateUsages(oldCSR *certificates.CertificateSigningRequest) bool {
	switch {
	case oldCSR != nil && hasDuplicateUsage(oldCSR.Spec.Usages):
		return true // compatibility with existing data
	default:
		return false
	}
}

func hasDuplicateUsage(usages []certificates.KeyUsage) bool {
	seen := make(map[certificates.KeyUsage]bool, len(usages))
	for _, usage := range usages {
		if seen[usage] {
			return true
		}
		seen[usage] = true
	}
	return false
}

type ValidateClusterTrustBundleOptions struct {
	SuppressBundleParsing bool
}

// ValidateClusterTrustBundle runs all validation checks on bundle.
func ValidateClusterTrustBundle(bundle *certificates.ClusterTrustBundle, opts ValidateClusterTrustBundleOptions) field.ErrorList {
	var allErrors field.ErrorList

	metaErrors := apivalidation.ValidateObjectMeta(&bundle.ObjectMeta, false, apivalidation.ValidateClusterTrustBundleName(bundle.Spec.SignerName), field.NewPath("metadata"))
	allErrors = append(allErrors, metaErrors...)

	if bundle.Spec.SignerName != "" {
		signerNameErrors := apivalidation.ValidateSignerName(field.NewPath("spec", "signerName"), bundle.Spec.SignerName)
		allErrors = append(allErrors, signerNameErrors...)
	}

	if !opts.SuppressBundleParsing {
		pemErrors := validateTrustBundle(field.NewPath("spec", "trustBundle"), bundle.Spec.TrustBundle)
		allErrors = append(allErrors, pemErrors...)
	}

	return allErrors
}

// ValidateClusterTrustBundleUpdate runs all update validation checks on an
// update.
func ValidateClusterTrustBundleUpdate(newBundle, oldBundle *certificates.ClusterTrustBundle) field.ErrorList {
	// If the caller isn't changing the TrustBundle field, don't parse it.
	// This helps smoothly handle changes in Go's PEM or X.509 parsing
	// libraries.
	opts := ValidateClusterTrustBundleOptions{}
	if newBundle.Spec.TrustBundle == oldBundle.Spec.TrustBundle {
		opts.SuppressBundleParsing = true
	}

	var allErrors field.ErrorList
	allErrors = append(allErrors, ValidateClusterTrustBundle(newBundle, opts)...)
	allErrors = append(allErrors, apivalidation.ValidateObjectMetaUpdate(&newBundle.ObjectMeta, &oldBundle.ObjectMeta, field.NewPath("metadata"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newBundle.Spec.SignerName, oldBundle.Spec.SignerName, field.NewPath("spec", "signerName"))...)
	return allErrors
}

// validateTrustBundle rejects intra-block headers, blocks
// that don't parse as X.509 CA certificates, and duplicate trust anchors.  It
// requires that at least one trust anchor is provided.
func validateTrustBundle(path *field.Path, in string) field.ErrorList {
	var allErrors field.ErrorList

	if len(in) > certificates.MaxTrustBundleSize {
		allErrors = append(allErrors, field.TooLong(path, fmt.Sprintf("<value omitted, len %d>", len(in)), certificates.MaxTrustBundleSize))
		return allErrors
	}

	blockDedupe := map[string][]int{}

	rest := []byte(in)
	var b *pem.Block
	i := -1
	for {
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		i++

		if b.Type != "CERTIFICATE" {
			allErrors = append(allErrors, field.Invalid(path, "<value omitted>", fmt.Sprintf("entry %d has bad block type: %v", i, b.Type)))
			continue
		}

		if len(b.Headers) != 0 {
			allErrors = append(allErrors, field.Invalid(path, "<value omitted>", fmt.Sprintf("entry %d has PEM block headers", i)))
			continue
		}

		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			allErrors = append(allErrors, field.Invalid(path, "<value omitted>", fmt.Sprintf("entry %d does not parse as X.509", i)))
			continue
		}

		if !cert.IsCA {
			allErrors = append(allErrors, field.Invalid(path, "<value omitted>", fmt.Sprintf("entry %d does not have the CA bit set", i)))
			continue
		}

		if !cert.BasicConstraintsValid {
			allErrors = append(allErrors, field.Invalid(path, "<value omitted>", fmt.Sprintf("entry %d has invalid basic constraints", i)))
			continue
		}

		blockDedupe[string(b.Bytes)] = append(blockDedupe[string(b.Bytes)], i)
	}

	// If we had a malformed block, don't also output potentially-redundant
	// errors about duplicate or missing trust anchors.
	if len(allErrors) != 0 {
		return allErrors
	}

	if len(blockDedupe) == 0 {
		allErrors = append(allErrors, field.Invalid(path, "<value omitted>", "at least one trust anchor must be provided"))
	}

	for _, indices := range blockDedupe {
		if len(indices) > 1 {
			allErrors = append(allErrors, field.Invalid(path, "<value omitted>", fmt.Sprintf("duplicate trust anchor (indices %v)", indices)))
		}
	}

	return allErrors
}

// We don't care what you call your pod certificate requests.
func validatePodCertificateRequestName(name string, prefix bool) []string {
	return nil
}

// ValidatePCRCreate checks validation for create.
//
// When creating, all spec fields are validated, and all status fields must be
// empty.
func ValidatePCRCreate(req *certificates.PodCertificateRequest) field.ErrorList {
	var allErrors field.ErrorList

	metaErrors := apivalidation.ValidateObjectMeta(&req.ObjectMeta, true, validatePodCertificateRequestName, field.NewPath("metadata"))
	allErrors = append(allErrors, metaErrors...)

	signerNameErrors := apivalidation.ValidateSignerName(field.NewPath("spec", "signerName"), req.Spec.SignerName)
	allErrors = append(allErrors, signerNameErrors...)

	// PodName, PodUID, ServiceAccountName, ServiceAccountUID, NodeName, and
	// NodeUID have already been checked to be real values by the
	// noderestriction admission plugin.

	if req.Spec.MaxExpirationSeconds < 3600 {
		allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "maxExpirationSeconds"), req.Spec.MaxExpirationSeconds, "must be >= 3600 (1 hour)"))
	}

	// Check key and proof of possession.
	allErrors = append(allErrors, validatePCRSpecCrypto(req)...)

	// All status fields must be empty when created.
	if len(req.Status.Conditions) != 0 {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "conditions"), req.Status.Conditions, "must be empty upon create"))
	}
	if req.Status.CertificateChain != "" {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "certificateChain"), req.Status.CertificateChain, "must be emtpy upon create"))
	}
	if req.Status.IssuedAt != nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "issuedAt"), req.Status.IssuedAt, "must be unset upon create"))
	}
	if req.Status.NotBefore != nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "notBefore"), req.Status.NotBefore, "must be unset upon create"))
	}
	if req.Status.BeginRefreshAt != nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "beginRefreshAt"), req.Status.BeginRefreshAt, "must be unset upon create"))
	}
	if req.Status.NotAfter != nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "notAfter"), req.Status.NotAfter, "must be unset upon create"))
	}

	return allErrors
}

// ValidatePCRStandardUpdate validates normal updates to the PCR object.
//
// Normal updates can't do much, since .Spec is immutable and .Status must be
// updated using the /status subresource.  Basically it can just do normal
// metadata changes.
func ValidatePCRStandardUpdate(newReq, oldReq *certificates.PodCertificateRequest) field.ErrorList {
	var allErrors field.ErrorList
	allErrors = append(allErrors, apivalidation.ValidateObjectMetaUpdate(&newReq.ObjectMeta, &oldReq.ObjectMeta, field.NewPath("metadata"))...)

	// All spec fields are immutable after creation.
	allErrors = append(allErrors, validatePCRSpecImmutable(newReq, oldReq)...)

	// TODO(KEP-4317): A standard update may not change status.Conditions.

	// A standard update is not allowed to modify any of the status fields
	allErrors = append(allErrors, validatePCRStatusImmutable(newReq, oldReq)...)

	return allErrors
}

// ValidatePCRStatusUpdate validates /status updates to the
// PCR object.
//
// All .Status fields (except .Status.Conditions) are immutable once they are
// set, and they must all be set in one call.  .Status.Conditions may be freely
// set, except for conditions with a type of "Denied", "Failed", or
// "SuggestedKeyType", which are immutable once they are set, and must be true.
// "Denied" and "Failed" are mutually exclusive.
func ValidatePCRStatusUpdate(newReq, oldReq *certificates.PodCertificateRequest) field.ErrorList {
	var allErrors field.ErrorList
	allErrors = append(allErrors, apivalidation.ValidateObjectMetaUpdate(&newReq.ObjectMeta, &oldReq.ObjectMeta, field.NewPath("metadata"))...)

	// All spec fields are immutable after creation.
	allErrors = append(allErrors, validatePCRSpecImmutable(newReq, oldReq)...)

	// TODO(KEP-4317): A status update may set arbitrary conditions, but it may
	// not change the Denied, Failed, or SuggestedKeyType conditions once they
	// are set.
	//
	// Actually, is there value in this?  Consult w/ @enj and @liggitt

	// A status update may not set the status fields if they are already set.
	if oldReq.Status.CertificateChain != "" ||
		oldReq.Status.IssuedAt != nil ||
		oldReq.Status.NotBefore != nil ||
		oldReq.Status.BeginRefreshAt != nil ||
		oldReq.Status.NotAfter != nil {
		allErrors = append(allErrors, validatePCRStatusImmutable(newReq, oldReq)...)
		return allErrors
	}

	// The update is valid, so validate the new values.

	allErrors = append(allErrors, validatePCRStatusCrypto(newReq)...)

	if newReq.Status.IssuedAt.Time.IsZero() {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "issuedAt"), newReq.Status.IssuedAt, "must be non-zero"))
	}

	return allErrors
}

func validatePCRSpecImmutable(newReq, oldReq *certificates.PodCertificateRequest) field.ErrorList {
	var allErrors field.ErrorList
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.SignerName, oldReq.Spec.SignerName, field.NewPath("spec", "signerName"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.PodName, oldReq.Spec.PodName, field.NewPath("spec", "podName"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.PodUID, oldReq.Spec.PodUID, field.NewPath("spec", "podUID"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.ServiceAccountName, oldReq.Spec.ServiceAccountName, field.NewPath("spec", "serviceAccountName"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.NodeName, oldReq.Spec.NodeName, field.NewPath("spec", "nodeName"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.MaxExpirationSeconds, oldReq.Spec.MaxExpirationSeconds, field.NewPath("spec", "maxExpirationSeconds"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.PKIXPublicKey, oldReq.Spec.PKIXPublicKey, field.NewPath("spec", "pkixPublicKey"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Spec.ProofOfPossession, oldReq.Spec.ProofOfPossession, field.NewPath("spec", "proofOfPossession"))...)
	return allErrors
}

func validatePCRStatusImmutable(newReq, oldReq *certificates.PodCertificateRequest) field.ErrorList {
	var allErrors field.ErrorList
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Status.CertificateChain, oldReq.Status.CertificateChain, field.NewPath("status", "certificateChain"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Status.IssuedAt, oldReq.Status.IssuedAt, field.NewPath("status", "issuedAt"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Status.NotBefore, oldReq.Status.NotBefore, field.NewPath("status", "notBefore"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Status.BeginRefreshAt, oldReq.Status.BeginRefreshAt, field.NewPath("status", "beginRefreshAt"))...)
	allErrors = append(allErrors, apivalidation.ValidateImmutableField(newReq.Status.NotAfter, oldReq.Status.NotAfter, field.NewPath("status", "notAfter"))...)
	return allErrors
}

func validatePCRSpecCrypto(req *certificates.PodCertificateRequest) field.ErrorList {
	var allErrors field.ErrorList

	pubKeyAny, err := x509.ParsePKIXPublicKey(req.Spec.PKIXPublicKey)
	if err != nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "pkixPublicKey"), req.Spec.PKIXPublicKey, fmt.Sprintf("could not parse as PKIX: %v", err)))
	}

	wantProofMsg := []byte(req.Spec.PodUID)

	switch pubKey := pubKeyAny.(type) {
	case *rsa.PublicKey:
		// Check RSA key properties
		switch pubKey.N.BitLen() {
		case 3072, 4096:
			// OK
		default:
			allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "pkixPublicKey"), req.Spec.PKIXPublicKey, fmt.Sprintf("bad RSA modulus size %d; valid values are 3072 and 4096", pubKey.N.BitLen())))
			return allErrors
		}

		// Check proof of possession
		wantProofHash := sha256.Sum256(wantProofMsg)
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, wantProofHash[:], req.Spec.ProofOfPossession); err != nil {
			allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "proofOfPossession"), req.Spec.ProofOfPossession, fmt.Sprintf("bad proof of posession signature: %v", err)))
			return allErrors
		}

		return allErrors

	case *ecdsa.PublicKey:
		// Check ECDSA key properties
		switch pubKey.Curve {
		case elliptic.P256(), elliptic.P384():
			// OK
		default:
			allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "pkixPublicKey"), req.Spec.PKIXPublicKey, "bad ECDSA curve; valid values are P256 and P384"))
			return allErrors
		}

		// Check proof of possession
		wantProofHash := sha256.Sum256(wantProofMsg)
		if !ecdsa.VerifyASN1(pubKey, wantProofHash[:], req.Spec.ProofOfPossession) {
			allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "proofOfPossession"), req.Spec.ProofOfPossession, "bad proof of possession signature"))
			return allErrors
		}

		return allErrors

	case ed25519.PublicKey:
		// ED25519 has no key properties to verify

		// Check proof of possession
		if !ed25519.Verify(pubKey, wantProofMsg, req.Spec.ProofOfPossession) {
			allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "proofOfPossession"), req.Spec.ProofOfPossession, "bad proof of possession signature"))
			return allErrors
		}

		return allErrors

	default:
		allErrors = append(allErrors, field.Invalid(field.NewPath("spec", "pkixPublicKey"), req.Spec.PKIXPublicKey, fmt.Sprintf("bad type %T; only *rsa.PublicKey, *ecdsa.PublicKey, and ed25519.PublicKey are supported", pubKey)))
		return allErrors
	}
}

func validatePCRStatusCrypto(req *certificates.PodCertificateRequest) field.ErrorList {
	var allErrors field.ErrorList

	var leafBlock *pem.Block
	var block *pem.Block
	var rest = []byte(req.Status.CertificateChain)
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			allErrors = append(allErrors, field.Invalid(field.NewPath("status", "certificateChain"), req.Status.CertificateChain, "contains non-CERTIFICATE block"))
			return allErrors
		}

		if leafBlock == nil {
			leafBlock = block
		}
	}

	if leafBlock == nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "certificateChain"), req.Status.CertificateChain, "does not contain at least one CERTIFICATE block"))
		return allErrors
	}

	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "certificateChain"), req.Status.CertificateChain, fmt.Sprintf("leaf certificate not parseable as X.509: %v", err)))
	}

	// TODO(KEP-4317): Leaf certificate issued to PKIXPublicKey?
	//
	// Is this valuable?  It's not a security-critical property.

	if !leafCert.NotBefore.Equal(req.Status.NotBefore.Time) {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "notBefore"), req.Status.NotBefore, "not consistent with leaf certificate"))
	}
	if !leafCert.NotAfter.Equal(req.Status.NotAfter.Time) {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "notAfter"), req.Status.NotAfter, "not consistent with leaf certificate"))
	}

	if req.Status.BeginRefreshAt.Time.Before(leafCert.NotBefore.Add(10 * time.Minute)) {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "beginRefreshAt"), req.Status.BeginRefreshAt, "too early; earliest valid value is NotBefore + 10 minutes"))
	}
	if req.Status.BeginRefreshAt.Time.After(leafCert.NotAfter.Add(-10 * time.Minute)) {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "beginRefreshAt"), req.Status.BeginRefreshAt, "too late;  latest valid value is NotAfter + 10 minutes"))
	}

	if leafCert.NotAfter.Sub(leafCert.NotBefore) > time.Duration(time.Duration(req.Spec.MaxExpirationSeconds)*time.Second) {
		allErrors = append(allErrors, field.Invalid(field.NewPath("status", "certificateChain"), req.Status.CertificateChain, "issued certificate has longer lifetime than permitted by spec.maxExpirationSeconds"))
	}

	return allErrors
}
