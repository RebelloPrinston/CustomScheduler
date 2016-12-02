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

package serviceaccount

import (
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"time"

	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/runtime/schema"

	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/v1"
	metav1 "k8s.io/kubernetes/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/fields"
	kubelet "k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/serviceaccount"
	"k8s.io/kubernetes/pkg/util/sets"
	"k8s.io/kubernetes/pkg/watch"
)

// DefaultServiceAccountName is the name of the default service account to set on pods which do not specify a service account
const DefaultServiceAccountName = "default"

// EnforceMountableSecretsAnnotation is a default annotation that indicates that a service account should enforce mountable secrets.
// The value must be true to have this annotation take effect
const EnforceMountableSecretsAnnotation = "kubernetes.io/enforce-mountable-secrets"

// DefaultAPITokenMountPath is the path that ServiceAccountToken secrets are automounted to.
// The token file would then be accessible at /var/run/secrets/kubernetes.io/serviceaccount
const DefaultAPITokenMountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// PluginName is the name of this admission plugin
const PluginName = "ServiceAccount"

func init() {
	admission.RegisterPlugin(PluginName, func(client clientset.Interface, config io.Reader) (admission.Interface, error) {
		serviceAccountAdmission := NewServiceAccount(client)
		serviceAccountAdmission.Run()
		return serviceAccountAdmission, nil
	})
}

var _ = admission.Interface(&serviceAccount{})

type serviceAccount struct {
	*admission.Handler

	// LimitSecretReferences rejects pods that reference secrets their service accounts do not reference
	LimitSecretReferences bool
	// RequireAPIToken determines whether pod creation attempts are rejected if no API token exists for the pod's service account
	RequireAPIToken bool
	// MountServiceAccountToken creates Volume and VolumeMounts for the first referenced ServiceAccountToken for the pod's service account
	MountServiceAccountToken bool

	client clientset.Interface

	serviceAccounts cache.Indexer
	secrets         cache.Indexer

	stopChan                 chan struct{}
	serviceAccountsReflector *cache.Reflector
	secretsReflector         *cache.Reflector
}

// NewServiceAccount returns an admission.Interface implementation which limits admission of Pod CREATE requests based on the pod's ServiceAccount:
// 1. If the pod does not specify a ServiceAccount, it sets the pod's ServiceAccount to "default"
// 2. It ensures the ServiceAccount referenced by the pod exists
// 3. If LimitSecretReferences is true, it rejects the pod if the pod references Secret objects which the pod's ServiceAccount does not reference
// 4. If the pod does not contain any ImagePullSecrets, the ImagePullSecrets of the service account are added.
// 5. If MountServiceAccountToken is true, it adds a VolumeMount with the pod's ServiceAccount's api token secret to containers
func NewServiceAccount(cl clientset.Interface) *serviceAccount {
	serviceAccountsIndexer, serviceAccountsReflector := cache.NewNamespaceKeyedIndexerAndReflector(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				internalOptions := api.ListOptions{}
				v1.Convert_v1_ListOptions_To_api_ListOptions(&options, &internalOptions, nil)
				return cl.Core().ServiceAccounts(api.NamespaceAll).List(internalOptions)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				internalOptions := api.ListOptions{}
				v1.Convert_v1_ListOptions_To_api_ListOptions(&options, &internalOptions, nil)
				return cl.Core().ServiceAccounts(api.NamespaceAll).Watch(internalOptions)
			},
		},
		&api.ServiceAccount{},
		0,
	)

	tokenSelector := fields.SelectorFromSet(map[string]string{api.SecretTypeField: string(api.SecretTypeServiceAccountToken)})
	secretsIndexer, secretsReflector := cache.NewNamespaceKeyedIndexerAndReflector(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				internalOptions := api.ListOptions{}
				v1.Convert_v1_ListOptions_To_api_ListOptions(&options, &internalOptions, nil)
				internalOptions.FieldSelector = tokenSelector
				return cl.Core().Secrets(api.NamespaceAll).List(internalOptions)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				internalOptions := api.ListOptions{}
				v1.Convert_v1_ListOptions_To_api_ListOptions(&options, &internalOptions, nil)
				internalOptions.FieldSelector = tokenSelector
				return cl.Core().Secrets(api.NamespaceAll).Watch(internalOptions)
			},
		},
		&api.Secret{},
		0,
	)

	return &serviceAccount{
		Handler: admission.NewHandler(admission.Create),
		// TODO: enable this once we've swept secret usage to account for adding secret references to service accounts
		LimitSecretReferences: false,
		// Auto mount service account API token secrets
		MountServiceAccountToken: true,
		// Reject pod creation until a service account token is available
		RequireAPIToken: true,

		client:                   cl,
		serviceAccounts:          serviceAccountsIndexer,
		serviceAccountsReflector: serviceAccountsReflector,
		secrets:                  secretsIndexer,
		secretsReflector:         secretsReflector,
	}
}

func (s *serviceAccount) Run() {
	if s.stopChan == nil {
		s.stopChan = make(chan struct{})
		s.serviceAccountsReflector.RunUntil(s.stopChan)
		s.secretsReflector.RunUntil(s.stopChan)
	}
}
func (s *serviceAccount) Stop() {
	if s.stopChan != nil {
		close(s.stopChan)
		s.stopChan = nil
	}
}

func (s *serviceAccount) Admit(a admission.Attributes) (err error) {
	if a.GetResource().GroupResource() != api.Resource("pods") {
		return nil
	}
	obj := a.GetObject()
	if obj == nil {
		return nil
	}
	pod, ok := obj.(*api.Pod)
	if !ok {
		return nil
	}

	// Don't modify the spec of mirror pods.
	// That makes the kubelet very angry and confused, and it immediately deletes the pod (because the spec doesn't match)
	// That said, don't allow mirror pods to reference ServiceAccounts or SecretVolumeSources either
	if _, isMirrorPod := pod.Annotations[kubelet.ConfigMirrorAnnotationKey]; isMirrorPod {
		if len(pod.Spec.ServiceAccountName) != 0 {
			return admission.NewForbidden(a, fmt.Errorf("a mirror pod may not reference service accounts"))
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.VolumeSource.Secret != nil {
				return admission.NewForbidden(a, fmt.Errorf("a mirror pod may not reference secrets"))
			}
		}
		return nil
	}

	// Set the default service account if needed
	if len(pod.Spec.ServiceAccountName) == 0 {
		pod.Spec.ServiceAccountName = DefaultServiceAccountName
	}

	// Ensure the referenced service account exists
	serviceAccount, err := s.getServiceAccount(a.GetNamespace(), pod.Spec.ServiceAccountName)
	if err != nil {
		return admission.NewForbidden(a, fmt.Errorf("error looking up service account %s/%s: %v", a.GetNamespace(), pod.Spec.ServiceAccountName, err))
	}
	if serviceAccount == nil {
		// TODO: convert to a ServerTimeout error (or other error that sends a Retry-After header)
		return admission.NewForbidden(a, fmt.Errorf("service account %s/%s was not found, retry after the service account is created", a.GetNamespace(), pod.Spec.ServiceAccountName))
	}

	if s.enforceMountableSecrets(serviceAccount) {
		if err := s.limitSecretReferences(serviceAccount, pod); err != nil {
			return admission.NewForbidden(a, err)
		}
	}

	if s.MountServiceAccountToken && shouldAutomount(serviceAccount, pod) {
		if err := s.mountServiceAccountToken(serviceAccount, pod); err != nil {
			if _, ok := err.(errors.APIStatus); ok {
				return err
			}
			return admission.NewForbidden(a, err)
		}
	}

	if len(pod.Spec.ImagePullSecrets) == 0 {
		pod.Spec.ImagePullSecrets = make([]api.LocalObjectReference, len(serviceAccount.ImagePullSecrets))
		copy(pod.Spec.ImagePullSecrets, serviceAccount.ImagePullSecrets)
	}

	return nil
}

func shouldAutomount(sa *api.ServiceAccount, pod *api.Pod) bool {
	// Pod's preference wins
	if pod.Spec.AutomountServiceAccountToken != nil {
		return *pod.Spec.AutomountServiceAccountToken
	}
	// Then service account's
	if sa.AutomountServiceAccountToken != nil {
		return *sa.AutomountServiceAccountToken
	}
	// Default to true for backwards compatibility
	return true
}

// enforceMountableSecrets indicates whether mountable secrets should be enforced for a particular service account
// A global setting of true will override any flag set on the individual service account
func (s *serviceAccount) enforceMountableSecrets(serviceAccount *api.ServiceAccount) bool {
	if s.LimitSecretReferences {
		return true
	}

	if value, ok := serviceAccount.Annotations[EnforceMountableSecretsAnnotation]; ok {
		enforceMountableSecretCheck, _ := strconv.ParseBool(value)
		return enforceMountableSecretCheck
	}

	return false
}

// getServiceAccount returns the ServiceAccount for the given namespace and name if it exists
func (s *serviceAccount) getServiceAccount(namespace string, name string) (*api.ServiceAccount, error) {
	key := &api.ServiceAccount{ObjectMeta: api.ObjectMeta{Namespace: namespace}}
	index, err := s.serviceAccounts.Index("namespace", key)
	if err != nil {
		return nil, err
	}

	for _, obj := range index {
		serviceAccount := obj.(*api.ServiceAccount)
		if serviceAccount.Name == name {
			return serviceAccount, nil
		}
	}

	// Could not find in cache, attempt to look up directly
	numAttempts := 1
	if name == DefaultServiceAccountName {
		// If this is the default serviceaccount, attempt more times, since it should be auto-created by the controller
		numAttempts = 10
	}
	retryInterval := time.Duration(rand.Int63n(100)+int64(100)) * time.Millisecond
	for i := 0; i < numAttempts; i++ {
		if i != 0 {
			time.Sleep(retryInterval)
		}
		serviceAccount, err := s.client.Core().ServiceAccounts(namespace).Get(name, metav1.GetOptions{})
		if err == nil {
			return serviceAccount, nil
		}
		if !errors.IsNotFound(err) {
			return nil, err
		}
	}

	return nil, nil
}

// getReferencedServiceAccountToken returns the name of the first referenced secret which is a ServiceAccountToken for the service account
func (s *serviceAccount) getReferencedServiceAccountToken(serviceAccount *api.ServiceAccount) (string, error) {
	if len(serviceAccount.Secrets) == 0 {
		return "", nil
	}

	tokens, err := s.getServiceAccountTokens(serviceAccount)
	if err != nil {
		return "", err
	}

	references := sets.NewString()
	for _, secret := range serviceAccount.Secrets {
		references.Insert(secret.Name)
	}
	for _, token := range tokens {
		if references.Has(token.Name) {
			return token.Name, nil
		}
	}

	return "", nil
}

// getServiceAccountTokens returns all ServiceAccountToken secrets for the given ServiceAccount
func (s *serviceAccount) getServiceAccountTokens(serviceAccount *api.ServiceAccount) ([]*api.Secret, error) {
	key := &api.Secret{ObjectMeta: api.ObjectMeta{Namespace: serviceAccount.Namespace}}
	index, err := s.secrets.Index("namespace", key)
	if err != nil {
		return nil, err
	}

	tokens := []*api.Secret{}
	for _, obj := range index {
		token := obj.(*api.Secret)

		if serviceaccount.InternalIsServiceAccountToken(token, serviceAccount) {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

func (s *serviceAccount) limitSecretReferences(serviceAccount *api.ServiceAccount, pod *api.Pod) error {
	// Ensure all secrets the pod references are allowed by the service account
	mountableSecrets := sets.NewString()
	for _, s := range serviceAccount.Secrets {
		mountableSecrets.Insert(s.Name)
	}
	for _, volume := range pod.Spec.Volumes {
		source := volume.VolumeSource
		if source.Secret == nil {
			continue
		}
		secretName := source.Secret.SecretName
		if !mountableSecrets.Has(secretName) {
			return fmt.Errorf("volume with secret.secretName=\"%s\" is not allowed because service account %s does not reference that secret", secretName, serviceAccount.Name)
		}
	}

	for _, container := range pod.Spec.InitContainers {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				if !mountableSecrets.Has(env.ValueFrom.SecretKeyRef.Name) {
					return fmt.Errorf("init container %s with envVar %s referencing secret.secretName=\"%s\" is not allowed because service account %s does not reference that secret", container.Name, env.Name, env.ValueFrom.SecretKeyRef.Name, serviceAccount.Name)
				}
			}
		}
	}

	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				if !mountableSecrets.Has(env.ValueFrom.SecretKeyRef.Name) {
					return fmt.Errorf("container %s with envVar %s referencing secret.secretName=\"%s\" is not allowed because service account %s does not reference that secret", container.Name, env.Name, env.ValueFrom.SecretKeyRef.Name, serviceAccount.Name)
				}
			}
		}
	}

	// limit pull secret references as well
	pullSecrets := sets.NewString()
	for _, s := range serviceAccount.ImagePullSecrets {
		pullSecrets.Insert(s.Name)
	}
	for i, pullSecretRef := range pod.Spec.ImagePullSecrets {
		if !pullSecrets.Has(pullSecretRef.Name) {
			return fmt.Errorf(`imagePullSecrets[%d].name="%s" is not allowed because service account %s does not reference that imagePullSecret`, i, pullSecretRef.Name, serviceAccount.Name)
		}
	}
	return nil
}

func (s *serviceAccount) mountServiceAccountToken(serviceAccount *api.ServiceAccount, pod *api.Pod) error {
	// Find the name of a referenced ServiceAccountToken secret we can mount
	serviceAccountToken, err := s.getReferencedServiceAccountToken(serviceAccount)
	if err != nil {
		return fmt.Errorf("Error looking up service account token for %s/%s: %v", serviceAccount.Namespace, serviceAccount.Name, err)
	}
	if len(serviceAccountToken) == 0 {
		// We don't have an API token to mount, so return
		if s.RequireAPIToken {
			// If a token is required, this is considered an error
			err := errors.NewServerTimeout(schema.GroupResource{Resource: "serviceaccounts"}, "create pod", 1)
			err.ErrStatus.Message = fmt.Sprintf("No API token found for service account %q, retry after the token is automatically created and added to the service account", serviceAccount.Name)
			return err
		}
		return nil
	}

	// Find the volume and volume name for the ServiceAccountTokenSecret if it already exists
	tokenVolumeName := ""
	hasTokenVolume := false
	allVolumeNames := sets.NewString()
	for _, volume := range pod.Spec.Volumes {
		allVolumeNames.Insert(volume.Name)
		if volume.Secret != nil && volume.Secret.SecretName == serviceAccountToken {
			tokenVolumeName = volume.Name
			hasTokenVolume = true
			break
		}
	}

	// Determine a volume name for the ServiceAccountTokenSecret in case we need it
	if len(tokenVolumeName) == 0 {
		// Try naming the volume the same as the serviceAccountToken, and uniquify if needed
		tokenVolumeName = serviceAccountToken
		if allVolumeNames.Has(tokenVolumeName) {
			tokenVolumeName = api.SimpleNameGenerator.GenerateName(fmt.Sprintf("%s-", serviceAccountToken))
		}
	}

	// Create the prototypical VolumeMount
	volumeMount := api.VolumeMount{
		Name:      tokenVolumeName,
		ReadOnly:  true,
		MountPath: DefaultAPITokenMountPath,
	}

	// Ensure every container mounts the APISecret volume
	needsTokenVolume := false
	for i, container := range pod.Spec.InitContainers {
		existingContainerMount := false
		for _, volumeMount := range container.VolumeMounts {
			// Existing mounts at the default mount path prevent mounting of the API token
			if volumeMount.MountPath == DefaultAPITokenMountPath {
				existingContainerMount = true
				break
			}
		}
		if !existingContainerMount {
			pod.Spec.InitContainers[i].VolumeMounts = append(pod.Spec.InitContainers[i].VolumeMounts, volumeMount)
			needsTokenVolume = true
		}
	}
	for i, container := range pod.Spec.Containers {
		existingContainerMount := false
		for _, volumeMount := range container.VolumeMounts {
			// Existing mounts at the default mount path prevent mounting of the API token
			if volumeMount.MountPath == DefaultAPITokenMountPath {
				existingContainerMount = true
				break
			}
		}
		if !existingContainerMount {
			pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, volumeMount)
			needsTokenVolume = true
		}
	}

	// Add the volume if a container needs it
	if !hasTokenVolume && needsTokenVolume {
		volume := api.Volume{
			Name: tokenVolumeName,
			VolumeSource: api.VolumeSource{
				Secret: &api.SecretVolumeSource{
					SecretName: serviceAccountToken,
				},
			},
		}
		pod.Spec.Volumes = append(pod.Spec.Volumes, volume)
	}
	return nil
}
