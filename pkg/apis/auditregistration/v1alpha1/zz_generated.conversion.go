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

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	v1alpha1 "k8s.io/api/auditregistration/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	auditregistration "k8s.io/kubernetes/pkg/apis/auditregistration"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*v1alpha1.AuditClass)(nil), (*auditregistration.AuditClass)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AuditClass_To_auditregistration_AuditClass(a.(*v1alpha1.AuditClass), b.(*auditregistration.AuditClass), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.AuditClass)(nil), (*v1alpha1.AuditClass)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_AuditClass_To_v1alpha1_AuditClass(a.(*auditregistration.AuditClass), b.(*v1alpha1.AuditClass), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.AuditClassList)(nil), (*auditregistration.AuditClassList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AuditClassList_To_auditregistration_AuditClassList(a.(*v1alpha1.AuditClassList), b.(*auditregistration.AuditClassList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.AuditClassList)(nil), (*v1alpha1.AuditClassList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_AuditClassList_To_v1alpha1_AuditClassList(a.(*auditregistration.AuditClassList), b.(*v1alpha1.AuditClassList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.AuditClassSpec)(nil), (*auditregistration.AuditClassSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AuditClassSpec_To_auditregistration_AuditClassSpec(a.(*v1alpha1.AuditClassSpec), b.(*auditregistration.AuditClassSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.AuditClassSpec)(nil), (*v1alpha1.AuditClassSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_AuditClassSpec_To_v1alpha1_AuditClassSpec(a.(*auditregistration.AuditClassSpec), b.(*v1alpha1.AuditClassSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.AuditSink)(nil), (*auditregistration.AuditSink)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AuditSink_To_auditregistration_AuditSink(a.(*v1alpha1.AuditSink), b.(*auditregistration.AuditSink), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.AuditSink)(nil), (*v1alpha1.AuditSink)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_AuditSink_To_v1alpha1_AuditSink(a.(*auditregistration.AuditSink), b.(*v1alpha1.AuditSink), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.AuditSinkList)(nil), (*auditregistration.AuditSinkList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AuditSinkList_To_auditregistration_AuditSinkList(a.(*v1alpha1.AuditSinkList), b.(*auditregistration.AuditSinkList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.AuditSinkList)(nil), (*v1alpha1.AuditSinkList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_AuditSinkList_To_v1alpha1_AuditSinkList(a.(*auditregistration.AuditSinkList), b.(*v1alpha1.AuditSinkList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.AuditSinkSpec)(nil), (*auditregistration.AuditSinkSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_AuditSinkSpec_To_auditregistration_AuditSinkSpec(a.(*v1alpha1.AuditSinkSpec), b.(*auditregistration.AuditSinkSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.AuditSinkSpec)(nil), (*v1alpha1.AuditSinkSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_AuditSinkSpec_To_v1alpha1_AuditSinkSpec(a.(*auditregistration.AuditSinkSpec), b.(*v1alpha1.AuditSinkSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.GroupResources)(nil), (*auditregistration.GroupResources)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_GroupResources_To_auditregistration_GroupResources(a.(*v1alpha1.GroupResources), b.(*auditregistration.GroupResources), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.GroupResources)(nil), (*v1alpha1.GroupResources)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_GroupResources_To_v1alpha1_GroupResources(a.(*auditregistration.GroupResources), b.(*v1alpha1.GroupResources), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.Policy)(nil), (*auditregistration.Policy)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Policy_To_auditregistration_Policy(a.(*v1alpha1.Policy), b.(*auditregistration.Policy), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.Policy)(nil), (*v1alpha1.Policy)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_Policy_To_v1alpha1_Policy(a.(*auditregistration.Policy), b.(*v1alpha1.Policy), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.PolicyRule)(nil), (*auditregistration.PolicyRule)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_PolicyRule_To_auditregistration_PolicyRule(a.(*v1alpha1.PolicyRule), b.(*auditregistration.PolicyRule), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.PolicyRule)(nil), (*v1alpha1.PolicyRule)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_PolicyRule_To_v1alpha1_PolicyRule(a.(*auditregistration.PolicyRule), b.(*v1alpha1.PolicyRule), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.RequestSelector)(nil), (*auditregistration.RequestSelector)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_RequestSelector_To_auditregistration_RequestSelector(a.(*v1alpha1.RequestSelector), b.(*auditregistration.RequestSelector), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.RequestSelector)(nil), (*v1alpha1.RequestSelector)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_RequestSelector_To_v1alpha1_RequestSelector(a.(*auditregistration.RequestSelector), b.(*v1alpha1.RequestSelector), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.ServiceReference)(nil), (*auditregistration.ServiceReference)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_ServiceReference_To_auditregistration_ServiceReference(a.(*v1alpha1.ServiceReference), b.(*auditregistration.ServiceReference), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.ServiceReference)(nil), (*v1alpha1.ServiceReference)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_ServiceReference_To_v1alpha1_ServiceReference(a.(*auditregistration.ServiceReference), b.(*v1alpha1.ServiceReference), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.Webhook)(nil), (*auditregistration.Webhook)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_Webhook_To_auditregistration_Webhook(a.(*v1alpha1.Webhook), b.(*auditregistration.Webhook), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.Webhook)(nil), (*v1alpha1.Webhook)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_Webhook_To_v1alpha1_Webhook(a.(*auditregistration.Webhook), b.(*v1alpha1.Webhook), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.WebhookClientConfig)(nil), (*auditregistration.WebhookClientConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_WebhookClientConfig_To_auditregistration_WebhookClientConfig(a.(*v1alpha1.WebhookClientConfig), b.(*auditregistration.WebhookClientConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.WebhookClientConfig)(nil), (*v1alpha1.WebhookClientConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_WebhookClientConfig_To_v1alpha1_WebhookClientConfig(a.(*auditregistration.WebhookClientConfig), b.(*v1alpha1.WebhookClientConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*v1alpha1.WebhookThrottleConfig)(nil), (*auditregistration.WebhookThrottleConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_WebhookThrottleConfig_To_auditregistration_WebhookThrottleConfig(a.(*v1alpha1.WebhookThrottleConfig), b.(*auditregistration.WebhookThrottleConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*auditregistration.WebhookThrottleConfig)(nil), (*v1alpha1.WebhookThrottleConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_auditregistration_WebhookThrottleConfig_To_v1alpha1_WebhookThrottleConfig(a.(*auditregistration.WebhookThrottleConfig), b.(*v1alpha1.WebhookThrottleConfig), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_AuditClass_To_auditregistration_AuditClass(in *v1alpha1.AuditClass, out *auditregistration.AuditClass, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_AuditClassSpec_To_auditregistration_AuditClassSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_AuditClass_To_auditregistration_AuditClass is an autogenerated conversion function.
func Convert_v1alpha1_AuditClass_To_auditregistration_AuditClass(in *v1alpha1.AuditClass, out *auditregistration.AuditClass, s conversion.Scope) error {
	return autoConvert_v1alpha1_AuditClass_To_auditregistration_AuditClass(in, out, s)
}

func autoConvert_auditregistration_AuditClass_To_v1alpha1_AuditClass(in *auditregistration.AuditClass, out *v1alpha1.AuditClass, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_auditregistration_AuditClassSpec_To_v1alpha1_AuditClassSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_auditregistration_AuditClass_To_v1alpha1_AuditClass is an autogenerated conversion function.
func Convert_auditregistration_AuditClass_To_v1alpha1_AuditClass(in *auditregistration.AuditClass, out *v1alpha1.AuditClass, s conversion.Scope) error {
	return autoConvert_auditregistration_AuditClass_To_v1alpha1_AuditClass(in, out, s)
}

func autoConvert_v1alpha1_AuditClassList_To_auditregistration_AuditClassList(in *v1alpha1.AuditClassList, out *auditregistration.AuditClassList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]auditregistration.AuditClass)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_AuditClassList_To_auditregistration_AuditClassList is an autogenerated conversion function.
func Convert_v1alpha1_AuditClassList_To_auditregistration_AuditClassList(in *v1alpha1.AuditClassList, out *auditregistration.AuditClassList, s conversion.Scope) error {
	return autoConvert_v1alpha1_AuditClassList_To_auditregistration_AuditClassList(in, out, s)
}

func autoConvert_auditregistration_AuditClassList_To_v1alpha1_AuditClassList(in *auditregistration.AuditClassList, out *v1alpha1.AuditClassList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]v1alpha1.AuditClass)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_auditregistration_AuditClassList_To_v1alpha1_AuditClassList is an autogenerated conversion function.
func Convert_auditregistration_AuditClassList_To_v1alpha1_AuditClassList(in *auditregistration.AuditClassList, out *v1alpha1.AuditClassList, s conversion.Scope) error {
	return autoConvert_auditregistration_AuditClassList_To_v1alpha1_AuditClassList(in, out, s)
}

func autoConvert_v1alpha1_AuditClassSpec_To_auditregistration_AuditClassSpec(in *v1alpha1.AuditClassSpec, out *auditregistration.AuditClassSpec, s conversion.Scope) error {
	out.RequestSelectors = *(*[]auditregistration.RequestSelector)(unsafe.Pointer(&in.RequestSelectors))
	return nil
}

// Convert_v1alpha1_AuditClassSpec_To_auditregistration_AuditClassSpec is an autogenerated conversion function.
func Convert_v1alpha1_AuditClassSpec_To_auditregistration_AuditClassSpec(in *v1alpha1.AuditClassSpec, out *auditregistration.AuditClassSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_AuditClassSpec_To_auditregistration_AuditClassSpec(in, out, s)
}

func autoConvert_auditregistration_AuditClassSpec_To_v1alpha1_AuditClassSpec(in *auditregistration.AuditClassSpec, out *v1alpha1.AuditClassSpec, s conversion.Scope) error {
	out.RequestSelectors = *(*[]v1alpha1.RequestSelector)(unsafe.Pointer(&in.RequestSelectors))
	return nil
}

// Convert_auditregistration_AuditClassSpec_To_v1alpha1_AuditClassSpec is an autogenerated conversion function.
func Convert_auditregistration_AuditClassSpec_To_v1alpha1_AuditClassSpec(in *auditregistration.AuditClassSpec, out *v1alpha1.AuditClassSpec, s conversion.Scope) error {
	return autoConvert_auditregistration_AuditClassSpec_To_v1alpha1_AuditClassSpec(in, out, s)
}

func autoConvert_v1alpha1_AuditSink_To_auditregistration_AuditSink(in *v1alpha1.AuditSink, out *auditregistration.AuditSink, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_AuditSinkSpec_To_auditregistration_AuditSinkSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_AuditSink_To_auditregistration_AuditSink is an autogenerated conversion function.
func Convert_v1alpha1_AuditSink_To_auditregistration_AuditSink(in *v1alpha1.AuditSink, out *auditregistration.AuditSink, s conversion.Scope) error {
	return autoConvert_v1alpha1_AuditSink_To_auditregistration_AuditSink(in, out, s)
}

func autoConvert_auditregistration_AuditSink_To_v1alpha1_AuditSink(in *auditregistration.AuditSink, out *v1alpha1.AuditSink, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_auditregistration_AuditSinkSpec_To_v1alpha1_AuditSinkSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_auditregistration_AuditSink_To_v1alpha1_AuditSink is an autogenerated conversion function.
func Convert_auditregistration_AuditSink_To_v1alpha1_AuditSink(in *auditregistration.AuditSink, out *v1alpha1.AuditSink, s conversion.Scope) error {
	return autoConvert_auditregistration_AuditSink_To_v1alpha1_AuditSink(in, out, s)
}

func autoConvert_v1alpha1_AuditSinkList_To_auditregistration_AuditSinkList(in *v1alpha1.AuditSinkList, out *auditregistration.AuditSinkList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]auditregistration.AuditSink, len(*in))
		for i := range *in {
			if err := Convert_v1alpha1_AuditSink_To_auditregistration_AuditSink(&(*in)[i], &(*out)[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_v1alpha1_AuditSinkList_To_auditregistration_AuditSinkList is an autogenerated conversion function.
func Convert_v1alpha1_AuditSinkList_To_auditregistration_AuditSinkList(in *v1alpha1.AuditSinkList, out *auditregistration.AuditSinkList, s conversion.Scope) error {
	return autoConvert_v1alpha1_AuditSinkList_To_auditregistration_AuditSinkList(in, out, s)
}

func autoConvert_auditregistration_AuditSinkList_To_v1alpha1_AuditSinkList(in *auditregistration.AuditSinkList, out *v1alpha1.AuditSinkList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]v1alpha1.AuditSink, len(*in))
		for i := range *in {
			if err := Convert_auditregistration_AuditSink_To_v1alpha1_AuditSink(&(*in)[i], &(*out)[i], s); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

// Convert_auditregistration_AuditSinkList_To_v1alpha1_AuditSinkList is an autogenerated conversion function.
func Convert_auditregistration_AuditSinkList_To_v1alpha1_AuditSinkList(in *auditregistration.AuditSinkList, out *v1alpha1.AuditSinkList, s conversion.Scope) error {
	return autoConvert_auditregistration_AuditSinkList_To_v1alpha1_AuditSinkList(in, out, s)
}

func autoConvert_v1alpha1_AuditSinkSpec_To_auditregistration_AuditSinkSpec(in *v1alpha1.AuditSinkSpec, out *auditregistration.AuditSinkSpec, s conversion.Scope) error {
	if err := Convert_v1alpha1_Policy_To_auditregistration_Policy(&in.Policy, &out.Policy, s); err != nil {
		return err
	}
	if err := Convert_v1alpha1_Webhook_To_auditregistration_Webhook(&in.Webhook, &out.Webhook, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_AuditSinkSpec_To_auditregistration_AuditSinkSpec is an autogenerated conversion function.
func Convert_v1alpha1_AuditSinkSpec_To_auditregistration_AuditSinkSpec(in *v1alpha1.AuditSinkSpec, out *auditregistration.AuditSinkSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_AuditSinkSpec_To_auditregistration_AuditSinkSpec(in, out, s)
}

func autoConvert_auditregistration_AuditSinkSpec_To_v1alpha1_AuditSinkSpec(in *auditregistration.AuditSinkSpec, out *v1alpha1.AuditSinkSpec, s conversion.Scope) error {
	if err := Convert_auditregistration_Policy_To_v1alpha1_Policy(&in.Policy, &out.Policy, s); err != nil {
		return err
	}
	if err := Convert_auditregistration_Webhook_To_v1alpha1_Webhook(&in.Webhook, &out.Webhook, s); err != nil {
		return err
	}
	return nil
}

// Convert_auditregistration_AuditSinkSpec_To_v1alpha1_AuditSinkSpec is an autogenerated conversion function.
func Convert_auditregistration_AuditSinkSpec_To_v1alpha1_AuditSinkSpec(in *auditregistration.AuditSinkSpec, out *v1alpha1.AuditSinkSpec, s conversion.Scope) error {
	return autoConvert_auditregistration_AuditSinkSpec_To_v1alpha1_AuditSinkSpec(in, out, s)
}

func autoConvert_v1alpha1_GroupResources_To_auditregistration_GroupResources(in *v1alpha1.GroupResources, out *auditregistration.GroupResources, s conversion.Scope) error {
	out.Group = in.Group
	out.Resources = *(*[]string)(unsafe.Pointer(&in.Resources))
	out.ObjectNames = *(*[]string)(unsafe.Pointer(&in.ObjectNames))
	return nil
}

// Convert_v1alpha1_GroupResources_To_auditregistration_GroupResources is an autogenerated conversion function.
func Convert_v1alpha1_GroupResources_To_auditregistration_GroupResources(in *v1alpha1.GroupResources, out *auditregistration.GroupResources, s conversion.Scope) error {
	return autoConvert_v1alpha1_GroupResources_To_auditregistration_GroupResources(in, out, s)
}

func autoConvert_auditregistration_GroupResources_To_v1alpha1_GroupResources(in *auditregistration.GroupResources, out *v1alpha1.GroupResources, s conversion.Scope) error {
	out.Group = in.Group
	out.Resources = *(*[]string)(unsafe.Pointer(&in.Resources))
	out.ObjectNames = *(*[]string)(unsafe.Pointer(&in.ObjectNames))
	return nil
}

// Convert_auditregistration_GroupResources_To_v1alpha1_GroupResources is an autogenerated conversion function.
func Convert_auditregistration_GroupResources_To_v1alpha1_GroupResources(in *auditregistration.GroupResources, out *v1alpha1.GroupResources, s conversion.Scope) error {
	return autoConvert_auditregistration_GroupResources_To_v1alpha1_GroupResources(in, out, s)
}

func autoConvert_v1alpha1_Policy_To_auditregistration_Policy(in *v1alpha1.Policy, out *auditregistration.Policy, s conversion.Scope) error {
	out.Level = auditregistration.Level(in.Level)
	out.Stages = *(*[]auditregistration.Stage)(unsafe.Pointer(&in.Stages))
	out.Rules = *(*[]auditregistration.PolicyRule)(unsafe.Pointer(&in.Rules))
	return nil
}

// Convert_v1alpha1_Policy_To_auditregistration_Policy is an autogenerated conversion function.
func Convert_v1alpha1_Policy_To_auditregistration_Policy(in *v1alpha1.Policy, out *auditregistration.Policy, s conversion.Scope) error {
	return autoConvert_v1alpha1_Policy_To_auditregistration_Policy(in, out, s)
}

func autoConvert_auditregistration_Policy_To_v1alpha1_Policy(in *auditregistration.Policy, out *v1alpha1.Policy, s conversion.Scope) error {
	out.Level = v1alpha1.Level(in.Level)
	out.Stages = *(*[]v1alpha1.Stage)(unsafe.Pointer(&in.Stages))
	out.Rules = *(*[]v1alpha1.PolicyRule)(unsafe.Pointer(&in.Rules))
	return nil
}

// Convert_auditregistration_Policy_To_v1alpha1_Policy is an autogenerated conversion function.
func Convert_auditregistration_Policy_To_v1alpha1_Policy(in *auditregistration.Policy, out *v1alpha1.Policy, s conversion.Scope) error {
	return autoConvert_auditregistration_Policy_To_v1alpha1_Policy(in, out, s)
}

func autoConvert_v1alpha1_PolicyRule_To_auditregistration_PolicyRule(in *v1alpha1.PolicyRule, out *auditregistration.PolicyRule, s conversion.Scope) error {
	out.WithAuditClass = in.WithAuditClass
	out.Level = auditregistration.Level(in.Level)
	out.Stages = *(*[]auditregistration.Stage)(unsafe.Pointer(&in.Stages))
	return nil
}

// Convert_v1alpha1_PolicyRule_To_auditregistration_PolicyRule is an autogenerated conversion function.
func Convert_v1alpha1_PolicyRule_To_auditregistration_PolicyRule(in *v1alpha1.PolicyRule, out *auditregistration.PolicyRule, s conversion.Scope) error {
	return autoConvert_v1alpha1_PolicyRule_To_auditregistration_PolicyRule(in, out, s)
}

func autoConvert_auditregistration_PolicyRule_To_v1alpha1_PolicyRule(in *auditregistration.PolicyRule, out *v1alpha1.PolicyRule, s conversion.Scope) error {
	out.WithAuditClass = in.WithAuditClass
	out.Level = v1alpha1.Level(in.Level)
	out.Stages = *(*[]v1alpha1.Stage)(unsafe.Pointer(&in.Stages))
	return nil
}

// Convert_auditregistration_PolicyRule_To_v1alpha1_PolicyRule is an autogenerated conversion function.
func Convert_auditregistration_PolicyRule_To_v1alpha1_PolicyRule(in *auditregistration.PolicyRule, out *v1alpha1.PolicyRule, s conversion.Scope) error {
	return autoConvert_auditregistration_PolicyRule_To_v1alpha1_PolicyRule(in, out, s)
}

func autoConvert_v1alpha1_RequestSelector_To_auditregistration_RequestSelector(in *v1alpha1.RequestSelector, out *auditregistration.RequestSelector, s conversion.Scope) error {
	out.Users = *(*[]string)(unsafe.Pointer(&in.Users))
	out.UserGroups = *(*[]string)(unsafe.Pointer(&in.UserGroups))
	out.Verbs = *(*[]string)(unsafe.Pointer(&in.Verbs))
	out.Resources = *(*[]auditregistration.GroupResources)(unsafe.Pointer(&in.Resources))
	out.Namespaces = *(*[]string)(unsafe.Pointer(&in.Namespaces))
	out.NonResourceURLs = *(*[]string)(unsafe.Pointer(&in.NonResourceURLs))
	return nil
}

// Convert_v1alpha1_RequestSelector_To_auditregistration_RequestSelector is an autogenerated conversion function.
func Convert_v1alpha1_RequestSelector_To_auditregistration_RequestSelector(in *v1alpha1.RequestSelector, out *auditregistration.RequestSelector, s conversion.Scope) error {
	return autoConvert_v1alpha1_RequestSelector_To_auditregistration_RequestSelector(in, out, s)
}

func autoConvert_auditregistration_RequestSelector_To_v1alpha1_RequestSelector(in *auditregistration.RequestSelector, out *v1alpha1.RequestSelector, s conversion.Scope) error {
	out.Users = *(*[]string)(unsafe.Pointer(&in.Users))
	out.UserGroups = *(*[]string)(unsafe.Pointer(&in.UserGroups))
	out.Verbs = *(*[]string)(unsafe.Pointer(&in.Verbs))
	out.Resources = *(*[]v1alpha1.GroupResources)(unsafe.Pointer(&in.Resources))
	out.Namespaces = *(*[]string)(unsafe.Pointer(&in.Namespaces))
	out.NonResourceURLs = *(*[]string)(unsafe.Pointer(&in.NonResourceURLs))
	return nil
}

// Convert_auditregistration_RequestSelector_To_v1alpha1_RequestSelector is an autogenerated conversion function.
func Convert_auditregistration_RequestSelector_To_v1alpha1_RequestSelector(in *auditregistration.RequestSelector, out *v1alpha1.RequestSelector, s conversion.Scope) error {
	return autoConvert_auditregistration_RequestSelector_To_v1alpha1_RequestSelector(in, out, s)
}

func autoConvert_v1alpha1_ServiceReference_To_auditregistration_ServiceReference(in *v1alpha1.ServiceReference, out *auditregistration.ServiceReference, s conversion.Scope) error {
	out.Namespace = in.Namespace
	out.Name = in.Name
	out.Path = (*string)(unsafe.Pointer(in.Path))
	if err := v1.Convert_Pointer_int32_To_int32(&in.Port, &out.Port, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_ServiceReference_To_auditregistration_ServiceReference is an autogenerated conversion function.
func Convert_v1alpha1_ServiceReference_To_auditregistration_ServiceReference(in *v1alpha1.ServiceReference, out *auditregistration.ServiceReference, s conversion.Scope) error {
	return autoConvert_v1alpha1_ServiceReference_To_auditregistration_ServiceReference(in, out, s)
}

func autoConvert_auditregistration_ServiceReference_To_v1alpha1_ServiceReference(in *auditregistration.ServiceReference, out *v1alpha1.ServiceReference, s conversion.Scope) error {
	out.Namespace = in.Namespace
	out.Name = in.Name
	out.Path = (*string)(unsafe.Pointer(in.Path))
	if err := v1.Convert_int32_To_Pointer_int32(&in.Port, &out.Port, s); err != nil {
		return err
	}
	return nil
}

// Convert_auditregistration_ServiceReference_To_v1alpha1_ServiceReference is an autogenerated conversion function.
func Convert_auditregistration_ServiceReference_To_v1alpha1_ServiceReference(in *auditregistration.ServiceReference, out *v1alpha1.ServiceReference, s conversion.Scope) error {
	return autoConvert_auditregistration_ServiceReference_To_v1alpha1_ServiceReference(in, out, s)
}

func autoConvert_v1alpha1_Webhook_To_auditregistration_Webhook(in *v1alpha1.Webhook, out *auditregistration.Webhook, s conversion.Scope) error {
	out.Throttle = (*auditregistration.WebhookThrottleConfig)(unsafe.Pointer(in.Throttle))
	if err := Convert_v1alpha1_WebhookClientConfig_To_auditregistration_WebhookClientConfig(&in.ClientConfig, &out.ClientConfig, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_Webhook_To_auditregistration_Webhook is an autogenerated conversion function.
func Convert_v1alpha1_Webhook_To_auditregistration_Webhook(in *v1alpha1.Webhook, out *auditregistration.Webhook, s conversion.Scope) error {
	return autoConvert_v1alpha1_Webhook_To_auditregistration_Webhook(in, out, s)
}

func autoConvert_auditregistration_Webhook_To_v1alpha1_Webhook(in *auditregistration.Webhook, out *v1alpha1.Webhook, s conversion.Scope) error {
	out.Throttle = (*v1alpha1.WebhookThrottleConfig)(unsafe.Pointer(in.Throttle))
	if err := Convert_auditregistration_WebhookClientConfig_To_v1alpha1_WebhookClientConfig(&in.ClientConfig, &out.ClientConfig, s); err != nil {
		return err
	}
	return nil
}

// Convert_auditregistration_Webhook_To_v1alpha1_Webhook is an autogenerated conversion function.
func Convert_auditregistration_Webhook_To_v1alpha1_Webhook(in *auditregistration.Webhook, out *v1alpha1.Webhook, s conversion.Scope) error {
	return autoConvert_auditregistration_Webhook_To_v1alpha1_Webhook(in, out, s)
}

func autoConvert_v1alpha1_WebhookClientConfig_To_auditregistration_WebhookClientConfig(in *v1alpha1.WebhookClientConfig, out *auditregistration.WebhookClientConfig, s conversion.Scope) error {
	out.URL = (*string)(unsafe.Pointer(in.URL))
	if in.Service != nil {
		in, out := &in.Service, &out.Service
		*out = new(auditregistration.ServiceReference)
		if err := Convert_v1alpha1_ServiceReference_To_auditregistration_ServiceReference(*in, *out, s); err != nil {
			return err
		}
	} else {
		out.Service = nil
	}
	out.CABundle = *(*[]byte)(unsafe.Pointer(&in.CABundle))
	return nil
}

// Convert_v1alpha1_WebhookClientConfig_To_auditregistration_WebhookClientConfig is an autogenerated conversion function.
func Convert_v1alpha1_WebhookClientConfig_To_auditregistration_WebhookClientConfig(in *v1alpha1.WebhookClientConfig, out *auditregistration.WebhookClientConfig, s conversion.Scope) error {
	return autoConvert_v1alpha1_WebhookClientConfig_To_auditregistration_WebhookClientConfig(in, out, s)
}

func autoConvert_auditregistration_WebhookClientConfig_To_v1alpha1_WebhookClientConfig(in *auditregistration.WebhookClientConfig, out *v1alpha1.WebhookClientConfig, s conversion.Scope) error {
	out.URL = (*string)(unsafe.Pointer(in.URL))
	if in.Service != nil {
		in, out := &in.Service, &out.Service
		*out = new(v1alpha1.ServiceReference)
		if err := Convert_auditregistration_ServiceReference_To_v1alpha1_ServiceReference(*in, *out, s); err != nil {
			return err
		}
	} else {
		out.Service = nil
	}
	out.CABundle = *(*[]byte)(unsafe.Pointer(&in.CABundle))
	return nil
}

// Convert_auditregistration_WebhookClientConfig_To_v1alpha1_WebhookClientConfig is an autogenerated conversion function.
func Convert_auditregistration_WebhookClientConfig_To_v1alpha1_WebhookClientConfig(in *auditregistration.WebhookClientConfig, out *v1alpha1.WebhookClientConfig, s conversion.Scope) error {
	return autoConvert_auditregistration_WebhookClientConfig_To_v1alpha1_WebhookClientConfig(in, out, s)
}

func autoConvert_v1alpha1_WebhookThrottleConfig_To_auditregistration_WebhookThrottleConfig(in *v1alpha1.WebhookThrottleConfig, out *auditregistration.WebhookThrottleConfig, s conversion.Scope) error {
	out.QPS = (*int64)(unsafe.Pointer(in.QPS))
	out.Burst = (*int64)(unsafe.Pointer(in.Burst))
	return nil
}

// Convert_v1alpha1_WebhookThrottleConfig_To_auditregistration_WebhookThrottleConfig is an autogenerated conversion function.
func Convert_v1alpha1_WebhookThrottleConfig_To_auditregistration_WebhookThrottleConfig(in *v1alpha1.WebhookThrottleConfig, out *auditregistration.WebhookThrottleConfig, s conversion.Scope) error {
	return autoConvert_v1alpha1_WebhookThrottleConfig_To_auditregistration_WebhookThrottleConfig(in, out, s)
}

func autoConvert_auditregistration_WebhookThrottleConfig_To_v1alpha1_WebhookThrottleConfig(in *auditregistration.WebhookThrottleConfig, out *v1alpha1.WebhookThrottleConfig, s conversion.Scope) error {
	out.QPS = (*int64)(unsafe.Pointer(in.QPS))
	out.Burst = (*int64)(unsafe.Pointer(in.Burst))
	return nil
}

// Convert_auditregistration_WebhookThrottleConfig_To_v1alpha1_WebhookThrottleConfig is an autogenerated conversion function.
func Convert_auditregistration_WebhookThrottleConfig_To_v1alpha1_WebhookThrottleConfig(in *auditregistration.WebhookThrottleConfig, out *v1alpha1.WebhookThrottleConfig, s conversion.Scope) error {
	return autoConvert_auditregistration_WebhookThrottleConfig_To_v1alpha1_WebhookThrottleConfig(in, out, s)
}
