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

package net

import (
	"errors"
	"net"
	"net/url"
	"os"
	"reflect"
	"syscall"
)

// IPNetEqual checks if the two input IPNets are representing the same subnet.
// For example,
//	10.0.0.1/24 and 10.0.0.0/24 are the same subnet.
//	10.0.0.1/24 and 10.0.0.0/25 are not the same subnet.
func IPNetEqual(ipnet1, ipnet2 *net.IPNet) bool {
	if ipnet1 == nil || ipnet2 == nil {
		return false
	}
	if reflect.DeepEqual(ipnet1.Mask, ipnet2.Mask) && ipnet1.Contains(ipnet2.IP) && ipnet2.Contains(ipnet1.IP) {
		return true
	}
	return false
}

// Returns if the given err is "connection reset by peer" error.
func IsConnectionReset(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		err = opErr.Err
	}
	var osErr *os.SyscallError
	if errors.As(err, &osErr) {
		err = osErr.Err
	}
	if errno, ok := err.(syscall.Errno); ok && errno == syscall.ECONNRESET {
		return true
	}
	return false
}

// Returns if the given err is "connection refused" error
func IsConnectionRefused(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		err = opErr.Err
	}
	var osErr *os.SyscallError
	if errors.As(err, &osErr) {
		err = osErr.Err
	}
	if errno, ok := err.(syscall.Errno); ok && errno == syscall.ECONNREFUSED {
		return true
	}
	return false
}

// IsNoRouteToHost returns true if the given error is "no route to host"
func IsNoRouteToHost(err error) bool {
	var osErr *os.SyscallError
	if errors.As(err, &osErr) {
		err = osErr.Err
	}

	// blocking the network traffic to a node gives: dial tcp 10.129.0.31:8443: connect: no route to host
	// no rsp has been sent to the client so it's okay to retry and pick up a different EP
	if errno, ok := err.(syscall.Errno); ok && errno == syscall.EHOSTUNREACH {
		return true
	}
	return false
}
