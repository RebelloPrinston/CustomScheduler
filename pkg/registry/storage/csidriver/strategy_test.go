/*
Copyright 2019 The Kubernetes Authors.

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

package csidriver

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/api/kubefeaturegates"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	utilfeature "k8s.io/component-base/featuregateinstance"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/apis/storage"
)

func getValidCSIDriver(name string) *storage.CSIDriver {
	enabled := true
	return &storage.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: storage.CSIDriverSpec{
			AttachRequired:  &enabled,
			PodInfoOnMount:  &enabled,
			StorageCapacity: &enabled,
		},
	}
}

func TestCSIDriverStrategy(t *testing.T) {
	ctx := genericapirequest.WithRequestInfo(genericapirequest.NewContext(), &genericapirequest.RequestInfo{
		APIGroup:   "storage.k8s.io",
		APIVersion: "v1",
		Resource:   "csidrivers",
	})
	if Strategy.NamespaceScoped() {
		t.Errorf("CSIDriver must not be namespace scoped")
	}
	if Strategy.AllowCreateOnUpdate() {
		t.Errorf("CSIDriver should not allow create on update")
	}

	csiDriver := getValidCSIDriver("valid-csidriver")

	Strategy.PrepareForCreate(ctx, csiDriver)

	errs := Strategy.Validate(ctx, csiDriver)
	if len(errs) != 0 {
		t.Errorf("unexpected error validating %v", errs)
	}

	// Update of spec is disallowed
	newCSIDriver := csiDriver.DeepCopy()
	attachNotRequired := false
	newCSIDriver.Spec.AttachRequired = &attachNotRequired

	Strategy.PrepareForUpdate(ctx, newCSIDriver, csiDriver)

	errs = Strategy.ValidateUpdate(ctx, newCSIDriver, csiDriver)
	if len(errs) == 0 {
		t.Errorf("Expected a validation error")
	}
}

func TestCSIDriverPrepareForCreate(t *testing.T) {
	ctx := genericapirequest.WithRequestInfo(genericapirequest.NewContext(), &genericapirequest.RequestInfo{
		APIGroup:   "storage.k8s.io",
		APIVersion: "v1",
		Resource:   "csidrivers",
	})

	attachRequired := true
	podInfoOnMount := true
	storageCapacity := true

	tests := []struct {
		name         string
		withCapacity bool
		withInline   bool
	}{
		{
			name:       "inline enabled",
			withInline: true,
		},
		{
			name:       "inline disabled",
			withInline: false,
		},
		{
			name:         "capacity enabled",
			withCapacity: true,
		},
		{
			name:         "capacity disabled",
			withCapacity: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, kubefeaturegates.CSIStorageCapacity, test.withCapacity)()
			defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, kubefeaturegates.CSIInlineVolume, test.withInline)()

			csiDriver := &storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &attachRequired,
					PodInfoOnMount:  &podInfoOnMount,
					StorageCapacity: &storageCapacity,
					VolumeLifecycleModes: []storage.VolumeLifecycleMode{
						storage.VolumeLifecyclePersistent,
					},
				},
			}
			Strategy.PrepareForCreate(ctx, csiDriver)
			errs := Strategy.Validate(ctx, csiDriver)
			if len(errs) != 0 {
				t.Errorf("unexpected validating errors: %v", errs)
			}
			if test.withCapacity {
				if csiDriver.Spec.StorageCapacity == nil || *csiDriver.Spec.StorageCapacity != storageCapacity {
					t.Errorf("StorageCapacity modified: %v", csiDriver.Spec.StorageCapacity)
				}
			} else {
				if csiDriver.Spec.StorageCapacity != nil {
					t.Errorf("StorageCapacity not stripped: %v", csiDriver.Spec.StorageCapacity)
				}
			}
			if test.withInline {
				if len(csiDriver.Spec.VolumeLifecycleModes) != 1 {
					t.Errorf("VolumeLifecycleModes modified: %v", csiDriver.Spec)
				}
			} else {
				if len(csiDriver.Spec.VolumeLifecycleModes) != 0 {
					t.Errorf("VolumeLifecycleModes not stripped: %v", csiDriver.Spec)
				}
			}
		})
	}
}

func TestCSIDriverPrepareForUpdate(t *testing.T) {
	ctx := genericapirequest.WithRequestInfo(genericapirequest.NewContext(), &genericapirequest.RequestInfo{
		APIGroup:   "storage.k8s.io",
		APIVersion: "v1",
		Resource:   "csidrivers",
	})

	attachRequired := true
	podInfoOnMount := true
	driverWithoutModes := &storage.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: storage.CSIDriverSpec{
			AttachRequired: &attachRequired,
			PodInfoOnMount: &podInfoOnMount,
		},
	}
	driverWithPersistent := &storage.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: storage.CSIDriverSpec{
			AttachRequired: &attachRequired,
			PodInfoOnMount: &podInfoOnMount,
			VolumeLifecycleModes: []storage.VolumeLifecycleMode{
				storage.VolumeLifecyclePersistent,
			},
		},
	}
	driverWithEphemeral := &storage.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: storage.CSIDriverSpec{
			AttachRequired: &attachRequired,
			PodInfoOnMount: &podInfoOnMount,
			VolumeLifecycleModes: []storage.VolumeLifecycleMode{
				storage.VolumeLifecycleEphemeral,
			},
		},
	}
	enabled := true
	disabled := false
	driverWithoutCapacity := &storage.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
	}
	driverWithCapacityEnabled := &storage.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: storage.CSIDriverSpec{
			StorageCapacity: &enabled,
		},
	}
	driverWithCapacityDisabled := &storage.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: storage.CSIDriverSpec{
			StorageCapacity: &disabled,
		},
	}

	var resultEmpty []storage.VolumeLifecycleMode
	resultPersistent := []storage.VolumeLifecycleMode{storage.VolumeLifecyclePersistent}
	resultEphemeral := []storage.VolumeLifecycleMode{storage.VolumeLifecycleEphemeral}

	tests := []struct {
		name                          string
		old, update                   *storage.CSIDriver
		withCapacity, withoutCapacity *bool
		withInline, withoutInline     []storage.VolumeLifecycleMode
	}{
		{
			name:            "before: no capacity, update: no capacity",
			old:             driverWithoutCapacity,
			update:          driverWithoutCapacity,
			withCapacity:    nil,
			withoutCapacity: nil,
		},
		{
			name:            "before: no capacity, update: enabled",
			old:             driverWithoutCapacity,
			update:          driverWithCapacityEnabled,
			withCapacity:    &enabled,
			withoutCapacity: nil,
		},
		{
			name:            "before: capacity enabled, update: disabled",
			old:             driverWithCapacityEnabled,
			update:          driverWithCapacityDisabled,
			withCapacity:    &disabled,
			withoutCapacity: &disabled,
		},
		{
			name:            "before: capacity enabled, update: no capacity",
			old:             driverWithCapacityEnabled,
			update:          driverWithoutCapacity,
			withCapacity:    nil,
			withoutCapacity: nil,
		},

		{
			name:          "before: no mode, update: no mode",
			old:           driverWithoutModes,
			update:        driverWithoutModes,
			withInline:    resultEmpty,
			withoutInline: resultEmpty,
		},
		{
			name:          "before: no mode, update: persistent",
			old:           driverWithoutModes,
			update:        driverWithPersistent,
			withInline:    resultPersistent,
			withoutInline: resultEmpty,
		},
		{
			name:          "before: persistent, update: ephemeral",
			old:           driverWithPersistent,
			update:        driverWithEphemeral,
			withInline:    resultEphemeral,
			withoutInline: resultEphemeral,
		},
		{
			name:          "before: persistent, update: no mode",
			old:           driverWithPersistent,
			update:        driverWithoutModes,
			withInline:    resultEmpty,
			withoutInline: resultEmpty,
		},
	}

	runAll := func(t *testing.T, withCapacity, withInline bool) {
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, kubefeaturegates.CSIStorageCapacity, withCapacity)()
				defer featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, kubefeaturegates.CSIInlineVolume, withInline)()

				csiDriver := test.update.DeepCopy()
				Strategy.PrepareForUpdate(ctx, csiDriver, test.old)
				if withCapacity {
					require.Equal(t, test.withCapacity, csiDriver.Spec.StorageCapacity)
				} else {
					require.Equal(t, test.withoutCapacity, csiDriver.Spec.StorageCapacity)
				}
				if withInline {
					require.Equal(t, test.withInline, csiDriver.Spec.VolumeLifecycleModes)
				} else {
					require.Equal(t, test.withoutInline, csiDriver.Spec.VolumeLifecycleModes)
				}
			})
		}
	}

	t.Run("with capacity", func(t *testing.T) {
		runAll(t, true, false)
	})
	t.Run("without capacity", func(t *testing.T) {
		runAll(t, false, false)
	})

	t.Run("with inline volumes", func(t *testing.T) {
		runAll(t, false, true)
	})
	t.Run("without inline volumes", func(t *testing.T) {
		runAll(t, false, false)
	})
}

func TestCSIDriverValidation(t *testing.T) {
	enabled := true
	disabled := true

	tests := []struct {
		name        string
		csiDriver   *storage.CSIDriver
		expectError bool
	}{
		{
			"valid csidriver",
			getValidCSIDriver("foo"),
			false,
		},
		{
			"true for all flags",
			&storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &enabled,
					PodInfoOnMount:  &enabled,
					StorageCapacity: &enabled,
				},
			},
			false,
		},
		{
			"false for all flags",
			&storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &disabled,
					PodInfoOnMount:  &disabled,
					StorageCapacity: &disabled,
				},
			},
			false,
		},
		{
			"invalid driver name",
			&storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "*foo#",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &enabled,
					PodInfoOnMount:  &enabled,
					StorageCapacity: &enabled,
				},
			},
			true,
		},
		{
			"invalid volume mode",
			&storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &enabled,
					PodInfoOnMount:  &enabled,
					StorageCapacity: &enabled,
					VolumeLifecycleModes: []storage.VolumeLifecycleMode{
						storage.VolumeLifecycleMode("no-such-mode"),
					},
				},
			},
			true,
		},
		{
			"persistent volume mode",
			&storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &enabled,
					PodInfoOnMount:  &enabled,
					StorageCapacity: &enabled,
					VolumeLifecycleModes: []storage.VolumeLifecycleMode{
						storage.VolumeLifecyclePersistent,
					},
				},
			},
			false,
		},
		{
			"ephemeral volume mode",
			&storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &enabled,
					PodInfoOnMount:  &enabled,
					StorageCapacity: &enabled,
					VolumeLifecycleModes: []storage.VolumeLifecycleMode{
						storage.VolumeLifecycleEphemeral,
					},
				},
			},
			false,
		},
		{
			"both volume modes",
			&storage.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: storage.CSIDriverSpec{
					AttachRequired:  &enabled,
					PodInfoOnMount:  &enabled,
					StorageCapacity: &enabled,
					VolumeLifecycleModes: []storage.VolumeLifecycleMode{
						storage.VolumeLifecyclePersistent,
						storage.VolumeLifecycleEphemeral,
					},
				},
			},
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			testValidation := func(csiDriver *storage.CSIDriver, apiVersion string) field.ErrorList {
				ctx := genericapirequest.WithRequestInfo(genericapirequest.NewContext(), &genericapirequest.RequestInfo{
					APIGroup:   "storage.k8s.io",
					APIVersion: "v1",
					Resource:   "csidrivers",
				})
				return Strategy.Validate(ctx, csiDriver)
			}

			err := testValidation(test.csiDriver, "v1")
			if len(err) > 0 && !test.expectError {
				t.Errorf("Validation of v1 object failed: %+v", err)
			}
			if len(err) == 0 && test.expectError {
				t.Errorf("Validation of v1 object unexpectedly succeeded")
			}
		})
	}
}
