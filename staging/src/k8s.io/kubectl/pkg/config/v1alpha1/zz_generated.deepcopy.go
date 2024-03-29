//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Preferences) DeepCopyInto(out *Preferences) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Preferences.
func (in *Preferences) DeepCopy() *Preferences {
	if in == nil {
		return nil
	}
	out := new(Preferences)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Preferences) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PreferencesCommandOverride) DeepCopyInto(out *PreferencesCommandOverride) {
	*out = *in
	if in.Flags != nil {
		in, out := &in.Flags, &out.Flags
		*out = make([]PreferencesCommandOverrideFlag, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PreferencesCommandOverride.
func (in *PreferencesCommandOverride) DeepCopy() *PreferencesCommandOverride {
	if in == nil {
		return nil
	}
	out := new(PreferencesCommandOverride)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PreferencesCommandOverrideFlag) DeepCopyInto(out *PreferencesCommandOverrideFlag) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PreferencesCommandOverrideFlag.
func (in *PreferencesCommandOverrideFlag) DeepCopy() *PreferencesCommandOverrideFlag {
	if in == nil {
		return nil
	}
	out := new(PreferencesCommandOverrideFlag)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PreferencesSpec) DeepCopyInto(out *PreferencesSpec) {
	*out = *in
	if in.Overrides != nil {
		in, out := &in.Overrides, &out.Overrides
		*out = make([]PreferencesCommandOverride, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PreferencesSpec.
func (in *PreferencesSpec) DeepCopy() *PreferencesSpec {
	if in == nil {
		return nil
	}
	out := new(PreferencesSpec)
	in.DeepCopyInto(out)
	return out
}
