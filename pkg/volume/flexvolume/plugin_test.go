/*
Copyright 2016 The Kubernetes Authors All rights reserved.

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

package flexvolume

import (
	"testing"

	"k8s.io/kubernetes/pkg/util/exec"
)

func TestInit(t *testing.T) {
	plugin, _ := testPlugin()
	plugin.runner = fakeRunner(
		assertDriverCall(t, successOutput(), "init"),
	)
	plugin.Init(plugin.host)
}

func fakeDeviceNameOutput(name string) exec.FakeCombinedOutputAction {
	return fakeResultOutput(&DriverStatus{
		Status: StatusSuccess,
		Device: name,
	})
}

func TestGetDeviceName(t *testing.T) {
	spec := fakeVolumeSpec()
	plugin, _ := testPlugin()
	plugin.runner = fakeRunner(
		assertDriverCall(t, fakeDeviceNameOutput("/dev/sdx"), getVolumeNameCmd,
			specJson(plugin, spec, nil)),
	)

	name, err := plugin.GetVolumeName(spec)
	if err != nil {
		t.Errorf("GetDeviceName() failed: %v", err)
	}
	expectedName := "~dev~sdx"
	if name != expectedName {
		t.Errorf("GetDeviceName() returned %v instead of %v", name, expectedName)
	}
}
