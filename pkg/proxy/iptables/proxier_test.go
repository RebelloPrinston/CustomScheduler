/*
Copyright 2015 The Kubernetes Authors.

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

package iptables

import (
	"testing"

	"fmt"
	"net"
	"strings"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/service"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util/exec"
	"k8s.io/kubernetes/pkg/util/intstr"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	iptablestest "k8s.io/kubernetes/pkg/util/iptables/testing"
)

func checkAllLines(t *testing.T, table utiliptables.Table, save []byte, expectedLines map[utiliptables.Chain]string) {
	chainLines := utiliptables.GetChainLines(table, save)
	for chain, line := range chainLines {
		if expected, exists := expectedLines[chain]; exists {
			if expected != line {
				t.Errorf("getChainLines expected chain line not present. For chain: %s Expected: %s Got: %s", chain, expected, line)
			}
		} else {
			t.Errorf("getChainLines expected chain not present: %s", chain)
		}
	}
}

func TestReadLinesFromByteBuffer(t *testing.T) {
	testFn := func(byteArray []byte, expected []string) {
		index := 0
		readIndex := 0
		for ; readIndex < len(byteArray); index++ {
			line, n := utiliptables.ReadLine(readIndex, byteArray)
			readIndex = n
			if expected[index] != line {
				t.Errorf("expected:%q, actual:%q", expected[index], line)
			}
		} // for
		if readIndex < len(byteArray) {
			t.Errorf("Byte buffer was only partially read. Buffer length is:%d, readIndex is:%d", len(byteArray), readIndex)
		}
		if index < len(expected) {
			t.Errorf("All expected strings were not compared. expected arr length:%d, matched count:%d", len(expected), index-1)
		}
	}

	byteArray1 := []byte("\n  Line 1  \n\n\n L ine4  \nLine 5 \n \n")
	expected1 := []string{"", "Line 1", "", "", "L ine4", "Line 5", ""}
	testFn(byteArray1, expected1)

	byteArray1 = []byte("")
	expected1 = []string{}
	testFn(byteArray1, expected1)

	byteArray1 = []byte("\n\n")
	expected1 = []string{"", ""}
	testFn(byteArray1, expected1)
}

func TestGetChainLines(t *testing.T) {
	iptables_save := `# Generated by iptables-save v1.4.7 on Wed Oct 29 14:56:01 2014
	*nat
	:PREROUTING ACCEPT [2136997:197881818]
	:POSTROUTING ACCEPT [4284525:258542680]
	:OUTPUT ACCEPT [5901660:357267963]
	-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
	COMMIT
	# Completed on Wed Oct 29 14:56:01 2014`
	expected := map[utiliptables.Chain]string{
		utiliptables.ChainPrerouting:  ":PREROUTING ACCEPT [2136997:197881818]",
		utiliptables.ChainPostrouting: ":POSTROUTING ACCEPT [4284525:258542680]",
		utiliptables.ChainOutput:      ":OUTPUT ACCEPT [5901660:357267963]",
	}
	checkAllLines(t, utiliptables.TableNAT, []byte(iptables_save), expected)
}

func TestGetChainLinesMultipleTables(t *testing.T) {
	iptables_save := `# Generated by iptables-save v1.4.21 on Fri Aug  7 14:47:37 2015
	*nat
	:PREROUTING ACCEPT [2:138]
	:INPUT ACCEPT [0:0]
	:OUTPUT ACCEPT [0:0]
	:POSTROUTING ACCEPT [0:0]
	:DOCKER - [0:0]
	:KUBE-NODEPORT-CONTAINER - [0:0]
	:KUBE-NODEPORT-HOST - [0:0]
	:KUBE-PORTALS-CONTAINER - [0:0]
	:KUBE-PORTALS-HOST - [0:0]
	:KUBE-SVC-1111111111111111 - [0:0]
	:KUBE-SVC-2222222222222222 - [0:0]
	:KUBE-SVC-3333333333333333 - [0:0]
	:KUBE-SVC-4444444444444444 - [0:0]
	:KUBE-SVC-5555555555555555 - [0:0]
	:KUBE-SVC-6666666666666666 - [0:0]
	-A PREROUTING -m comment --comment "handle ClusterIPs; NOTE: this must be before the NodePort rules" -j KUBE-PORTALS-CONTAINER
	-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
	-A PREROUTING -m addrtype --dst-type LOCAL -m comment --comment "handle service NodePorts; NOTE: this must be the last rule in the chain" -j KUBE-NODEPORT-CONTAINER
	-A OUTPUT -m comment --comment "handle ClusterIPs; NOTE: this must be before the NodePort rules" -j KUBE-PORTALS-HOST
	-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
	-A OUTPUT -m addrtype --dst-type LOCAL -m comment --comment "handle service NodePorts; NOTE: this must be the last rule in the chain" -j KUBE-NODEPORT-HOST
	-A POSTROUTING -s 10.246.1.0/24 ! -o cbr0 -j MASQUERADE
	-A POSTROUTING -s 10.0.2.15/32 -d 10.0.2.15/32 -m comment --comment "handle pod connecting to self" -j MASQUERADE
	-A KUBE-PORTALS-CONTAINER -d 10.247.0.1/32 -p tcp -m comment --comment "portal for default/kubernetes:" -m state --state NEW -m tcp --dport 443 -j KUBE-SVC-5555555555555555
	-A KUBE-PORTALS-CONTAINER -d 10.247.0.10/32 -p udp -m comment --comment "portal for kube-system/kube-dns:dns" -m state --state NEW -m udp --dport 53 -j KUBE-SVC-6666666666666666
	-A KUBE-PORTALS-CONTAINER -d 10.247.0.10/32 -p tcp -m comment --comment "portal for kube-system/kube-dns:dns-tcp" -m state --state NEW -m tcp --dport 53 -j KUBE-SVC-2222222222222222
	-A KUBE-PORTALS-HOST -d 10.247.0.1/32 -p tcp -m comment --comment "portal for default/kubernetes:" -m state --state NEW -m tcp --dport 443 -j KUBE-SVC-5555555555555555
	-A KUBE-PORTALS-HOST -d 10.247.0.10/32 -p udp -m comment --comment "portal for kube-system/kube-dns:dns" -m state --state NEW -m udp --dport 53 -j KUBE-SVC-6666666666666666
	-A KUBE-PORTALS-HOST -d 10.247.0.10/32 -p tcp -m comment --comment "portal for kube-system/kube-dns:dns-tcp" -m state --state NEW -m tcp --dport 53 -j KUBE-SVC-2222222222222222
	-A KUBE-SVC-1111111111111111 -p udp -m comment --comment "kube-system/kube-dns:dns" -m recent --set --name KUBE-SVC-1111111111111111 --mask 255.255.255.255 --rsource -j DNAT --to-destination 10.246.1.2:53
	-A KUBE-SVC-2222222222222222 -m comment --comment "kube-system/kube-dns:dns-tcp" -j KUBE-SVC-3333333333333333
	-A KUBE-SVC-3333333333333333 -p tcp -m comment --comment "kube-system/kube-dns:dns-tcp" -m recent --set --name KUBE-SVC-3333333333333333 --mask 255.255.255.255 --rsource -j DNAT --to-destination 10.246.1.2:53
	-A KUBE-SVC-4444444444444444 -p tcp -m comment --comment "default/kubernetes:" -m recent --set --name KUBE-SVC-4444444444444444 --mask 255.255.255.255 --rsource -j DNAT --to-destination 10.245.1.2:443
	-A KUBE-SVC-5555555555555555 -m comment --comment "default/kubernetes:" -j KUBE-SVC-4444444444444444
	-A KUBE-SVC-6666666666666666 -m comment --comment "kube-system/kube-dns:dns" -j KUBE-SVC-1111111111111111
	COMMIT
	# Completed on Fri Aug  7 14:47:37 2015
	# Generated by iptables-save v1.4.21 on Fri Aug  7 14:47:37 2015
	*filter
	:INPUT ACCEPT [17514:83115836]
	:FORWARD ACCEPT [0:0]
	:OUTPUT ACCEPT [8909:688225]
	:DOCKER - [0:0]
	-A FORWARD -o cbr0 -j DOCKER
	-A FORWARD -o cbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	-A FORWARD -i cbr0 ! -o cbr0 -j ACCEPT
	-A FORWARD -i cbr0 -o cbr0 -j ACCEPT
	COMMIT
	`
	expected := map[utiliptables.Chain]string{
		utiliptables.ChainPrerouting:                    ":PREROUTING ACCEPT [2:138]",
		utiliptables.Chain("INPUT"):                     ":INPUT ACCEPT [0:0]",
		utiliptables.Chain("OUTPUT"):                    ":OUTPUT ACCEPT [0:0]",
		utiliptables.ChainPostrouting:                   ":POSTROUTING ACCEPT [0:0]",
		utiliptables.Chain("DOCKER"):                    ":DOCKER - [0:0]",
		utiliptables.Chain("KUBE-NODEPORT-CONTAINER"):   ":KUBE-NODEPORT-CONTAINER - [0:0]",
		utiliptables.Chain("KUBE-NODEPORT-HOST"):        ":KUBE-NODEPORT-HOST - [0:0]",
		utiliptables.Chain("KUBE-PORTALS-CONTAINER"):    ":KUBE-PORTALS-CONTAINER - [0:0]",
		utiliptables.Chain("KUBE-PORTALS-HOST"):         ":KUBE-PORTALS-HOST - [0:0]",
		utiliptables.Chain("KUBE-SVC-1111111111111111"): ":KUBE-SVC-1111111111111111 - [0:0]",
		utiliptables.Chain("KUBE-SVC-2222222222222222"): ":KUBE-SVC-2222222222222222 - [0:0]",
		utiliptables.Chain("KUBE-SVC-3333333333333333"): ":KUBE-SVC-3333333333333333 - [0:0]",
		utiliptables.Chain("KUBE-SVC-4444444444444444"): ":KUBE-SVC-4444444444444444 - [0:0]",
		utiliptables.Chain("KUBE-SVC-5555555555555555"): ":KUBE-SVC-5555555555555555 - [0:0]",
		utiliptables.Chain("KUBE-SVC-6666666666666666"): ":KUBE-SVC-6666666666666666 - [0:0]",
	}
	checkAllLines(t, utiliptables.TableNAT, []byte(iptables_save), expected)
}

func TestGetRemovedEndpoints(t *testing.T) {
	testCases := []struct {
		currentEndpoints []string
		newEndpoints     []string
		removedEndpoints []string
	}{
		{
			currentEndpoints: []string{"10.0.2.1:80", "10.0.2.2:80"},
			newEndpoints:     []string{"10.0.2.1:80", "10.0.2.2:80"},
			removedEndpoints: []string{},
		},
		{
			currentEndpoints: []string{"10.0.2.1:80", "10.0.2.2:80", "10.0.2.3:80"},
			newEndpoints:     []string{"10.0.2.1:80", "10.0.2.2:80"},
			removedEndpoints: []string{"10.0.2.3:80"},
		},
		{
			currentEndpoints: []string{},
			newEndpoints:     []string{"10.0.2.1:80", "10.0.2.2:80"},
			removedEndpoints: []string{},
		},
		{
			currentEndpoints: []string{"10.0.2.1:80", "10.0.2.2:80"},
			newEndpoints:     []string{},
			removedEndpoints: []string{"10.0.2.1:80", "10.0.2.2:80"},
		},
		{
			currentEndpoints: []string{"10.0.2.1:80", "10.0.2.2:80", "10.0.2.2:443"},
			newEndpoints:     []string{"10.0.2.1:80", "10.0.2.2:80"},
			removedEndpoints: []string{"10.0.2.2:443"},
		},
	}

	for i := range testCases {
		res := getRemovedEndpoints(testCases[i].currentEndpoints, testCases[i].newEndpoints)
		if !slicesEquiv(res, testCases[i].removedEndpoints) {
			t.Errorf("Expected: %v, but getRemovedEndpoints returned: %v", testCases[i].removedEndpoints, res)
		}
	}
}

func TestExecConntrackTool(t *testing.T) {
	fcmd := exec.FakeCmd{
		CombinedOutputScript: []exec.FakeCombinedOutputAction{
			func() ([]byte, error) { return []byte("1 flow entries have been deleted"), nil },
			func() ([]byte, error) { return []byte("1 flow entries have been deleted"), nil },
			func() ([]byte, error) {
				return []byte(""), fmt.Errorf("conntrack v1.4.2 (conntrack-tools): 0 flow entries have been deleted.")
			},
		},
	}
	fexec := exec.FakeExec{
		CommandScript: []exec.FakeCommandAction{
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
		},
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
	}

	fakeProxier := Proxier{exec: &fexec}

	testCases := [][]string{
		{"-L", "-p", "udp"},
		{"-D", "-p", "udp", "-d", "10.0.240.1"},
		{"-D", "-p", "udp", "--orig-dst", "10.240.0.2", "--dst-nat", "10.0.10.2"},
	}

	expectErr := []bool{false, false, true}

	for i := range testCases {
		err := fakeProxier.execConntrackTool(testCases[i]...)

		if expectErr[i] {
			if err == nil {
				t.Errorf("expected err, got %v", err)
			}
		} else {
			if err != nil {
				t.Errorf("expected success, got %v", err)
			}
		}

		execCmd := strings.Join(fcmd.CombinedOutputLog[i], " ")
		expectCmd := fmt.Sprintf("%s %s", "conntrack", strings.Join(testCases[i], " "))

		if execCmd != expectCmd {
			t.Errorf("expect execute command: %s, but got: %s", expectCmd, execCmd)
		}
	}
}

func newFakeServiceInfo(service proxy.ServicePortName, ip net.IP, port int, protocol api.Protocol, onlyNodeLocalEndpoints bool) *serviceInfo {
	return &serviceInfo{
		sessionAffinityType:    api.ServiceAffinityNone, // default
		stickyMaxAgeMinutes:    180,                     // TODO: paramaterize this in the API.
		clusterIP:              ip,
		port:                   port,
		protocol:               protocol,
		onlyNodeLocalEndpoints: onlyNodeLocalEndpoints,
	}
}

func TestDeleteEndpointConnections(t *testing.T) {
	fcmd := exec.FakeCmd{
		CombinedOutputScript: []exec.FakeCombinedOutputAction{
			func() ([]byte, error) { return []byte("1 flow entries have been deleted"), nil },
			func() ([]byte, error) {
				return []byte(""), fmt.Errorf("conntrack v1.4.2 (conntrack-tools): 0 flow entries have been deleted.")
			},
		},
	}
	fexec := exec.FakeExec{
		CommandScript: []exec.FakeCommandAction{
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
		},
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
	}

	serviceMap := make(map[proxy.ServicePortName]*serviceInfo)
	svc1 := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "svc1"}, Port: "80"}
	svc2 := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "svc2"}, Port: "80"}
	serviceMap[svc1] = newFakeServiceInfo(svc1, net.IPv4(10, 20, 30, 40), 80, api.ProtocolUDP, false)
	serviceMap[svc2] = newFakeServiceInfo(svc1, net.IPv4(10, 20, 30, 41), 80, api.ProtocolTCP, false)

	fakeProxier := Proxier{exec: &fexec, serviceMap: serviceMap}

	testCases := []endpointServicePair{
		{
			endpoint:        "10.240.0.3:80",
			servicePortName: svc1,
		},
		{
			endpoint:        "10.240.0.4:80",
			servicePortName: svc1,
		},
		{
			endpoint:        "10.240.0.5:80",
			servicePortName: svc2,
		},
	}

	expectCommandExecCount := 0
	for i := range testCases {
		input := map[endpointServicePair]bool{testCases[i]: true}
		fakeProxier.deleteEndpointConnections(input)
		svcInfo := fakeProxier.serviceMap[testCases[i].servicePortName]
		if svcInfo.protocol == api.ProtocolUDP {
			svcIp := svcInfo.clusterIP.String()
			endpointIp := strings.Split(testCases[i].endpoint, ":")[0]
			expectCommand := fmt.Sprintf("conntrack -D --orig-dst %s --dst-nat %s -p udp", svcIp, endpointIp)
			execCommand := strings.Join(fcmd.CombinedOutputLog[expectCommandExecCount], " ")
			if expectCommand != execCommand {
				t.Errorf("Exepect comand: %s, but executed %s", expectCommand, execCommand)
			}
			expectCommandExecCount += 1
		}

		if expectCommandExecCount != fexec.CommandCalls {
			t.Errorf("Exepect comand executed %d times, but got %d", expectCommandExecCount, fexec.CommandCalls)
		}
	}
}

func TestDeleteServiceConnections(t *testing.T) {
	fcmd := exec.FakeCmd{
		CombinedOutputScript: []exec.FakeCombinedOutputAction{
			func() ([]byte, error) { return []byte("1 flow entries have been deleted"), nil },
			func() ([]byte, error) { return []byte("1 flow entries have been deleted"), nil },
			func() ([]byte, error) {
				return []byte(""), fmt.Errorf("conntrack v1.4.2 (conntrack-tools): 0 flow entries have been deleted.")
			},
		},
	}
	fexec := exec.FakeExec{
		CommandScript: []exec.FakeCommandAction{
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
			func(cmd string, args ...string) exec.Cmd { return exec.InitFakeCmd(&fcmd, cmd, args...) },
		},
		LookPathFunc: func(cmd string) (string, error) { return cmd, nil },
	}

	fakeProxier := Proxier{exec: &fexec}

	testCases := [][]string{
		{
			"10.240.0.3",
			"10.240.0.5",
		},
		{
			"10.240.0.4",
		},
	}

	svcCount := 0
	for i := range testCases {
		fakeProxier.deleteServiceConnections(testCases[i])
		for _, ip := range testCases[i] {
			expectCommand := fmt.Sprintf("conntrack -D --orig-dst %s -p udp", ip)
			execCommand := strings.Join(fcmd.CombinedOutputLog[svcCount], " ")
			if expectCommand != execCommand {
				t.Errorf("Exepect comand: %s, but executed %s", expectCommand, execCommand)
			}
			svcCount += 1
		}
		if svcCount != fexec.CommandCalls {
			t.Errorf("Exepect comand executed %d times, but got %d", svcCount, fexec.CommandCalls)
		}
	}
}

type fakeClosable struct {
	closed bool
}

func (c *fakeClosable) Close() error {
	c.closed = true
	return nil
}

func TestRevertPorts(t *testing.T) {
	testCases := []struct {
		replacementPorts []localPort
		existingPorts    []localPort
		expectToBeClose  []bool
	}{
		{
			replacementPorts: []localPort{
				{port: 5001},
				{port: 5002},
				{port: 5003},
			},
			existingPorts:   []localPort{},
			expectToBeClose: []bool{true, true, true},
		},
		{
			replacementPorts: []localPort{},
			existingPorts: []localPort{
				{port: 5001},
				{port: 5002},
				{port: 5003},
			},
			expectToBeClose: []bool{},
		},
		{
			replacementPorts: []localPort{
				{port: 5001},
				{port: 5002},
				{port: 5003},
			},
			existingPorts: []localPort{
				{port: 5001},
				{port: 5002},
				{port: 5003},
			},
			expectToBeClose: []bool{false, false, false},
		},
		{
			replacementPorts: []localPort{
				{port: 5001},
				{port: 5002},
				{port: 5003},
			},
			existingPorts: []localPort{
				{port: 5001},
				{port: 5003},
			},
			expectToBeClose: []bool{false, true, false},
		},
		{
			replacementPorts: []localPort{
				{port: 5001},
				{port: 5002},
				{port: 5003},
			},
			existingPorts: []localPort{
				{port: 5001},
				{port: 5002},
				{port: 5003},
				{port: 5004},
			},
			expectToBeClose: []bool{false, false, false},
		},
	}

	for i, tc := range testCases {
		replacementPortsMap := make(map[localPort]closeable)
		for _, lp := range tc.replacementPorts {
			replacementPortsMap[lp] = &fakeClosable{}
		}
		existingPortsMap := make(map[localPort]closeable)
		for _, lp := range tc.existingPorts {
			existingPortsMap[lp] = &fakeClosable{}
		}
		revertPorts(replacementPortsMap, existingPortsMap)
		for j, expectation := range tc.expectToBeClose {
			if replacementPortsMap[tc.replacementPorts[j]].(*fakeClosable).closed != expectation {
				t.Errorf("Expect replacement localport %v to be %v in test case %v", tc.replacementPorts[j], expectation, i)
			}
		}
		for _, lp := range tc.existingPorts {
			if existingPortsMap[lp].(*fakeClosable).closed == true {
				t.Errorf("Expect existing localport %v to be false in test case %v", lp, i)
			}
		}
	}

}

// fakePortOpener implements portOpener.
type fakePortOpener struct {
	openPorts []*localPort
}

// OpenLocalPort fakes out the listen() and bind() used by syncProxyRules
// to lock a local port.
func (f *fakePortOpener) OpenLocalPort(lp *localPort) (closeable, error) {
	f.openPorts = append(f.openPorts, lp)
	return nil, nil
}

func NewFakeProxier(ipt utiliptables.Interface) *Proxier {
	// TODO: Call NewProxier after refactoring out the goroutine
	// invocation into a Run() method.
	return &Proxier{
		exec:                        &exec.FakeExec{},
		serviceMap:                  make(map[proxy.ServicePortName]*serviceInfo),
		iptables:                    ipt,
		endpointsMap:                make(map[proxy.ServicePortName][]*endpointsInfo),
		clusterCIDR:                 "10.0.0.0/24",
		haveReceivedEndpointsUpdate: true,
		haveReceivedServiceUpdate:   true,
		hostname:                    "test-hostname",
		portsMap:                    make(map[localPort]closeable),
		portMapper:                  &fakePortOpener{[]*localPort{}},
	}
}

func hasJump(rules []iptablestest.Rule, destChain, destIP, destPort string) bool {
	match := false
	for _, r := range rules {
		if r[iptablestest.Jump] == destChain {
			match = true
			if destIP != "" {
				if strings.Contains(r[iptablestest.Destination], destIP) && (strings.Contains(r[iptablestest.DPort], destPort) || r[iptablestest.DPort] == "") {
					return true
				}
				match = false
			}
			if destPort != "" {
				if strings.Contains(r[iptablestest.DPort], destPort) && (strings.Contains(r[iptablestest.Destination], destIP) || r[iptablestest.Destination] == "") {
					return true
				}
				match = false
			}
		}
	}
	return match
}

func TestHasJump(t *testing.T) {
	testCases := map[string]struct {
		rules     []iptablestest.Rule
		destChain string
		destIP    string
		destPort  string
		expected  bool
	}{
		"case 1": {
			// Match the 1st rule(both dest IP and dest Port)
			rules: []iptablestest.Rule{
				{"-d ": "10.20.30.41/32", "--dport ": "80", "-p ": "tcp", "-j ": "REJECT"},
				{"--dport ": "3001", "-p ": "tcp", "-j ": "KUBE-MARK-MASQ"},
			},
			destChain: "REJECT",
			destIP:    "10.20.30.41",
			destPort:  "80",
			expected:  true,
		},
		"case 2": {
			// Match the 2nd rule(dest Port)
			rules: []iptablestest.Rule{
				{"-d ": "10.20.30.41/32", "-p ": "tcp", "-j ": "REJECT"},
				{"--dport ": "3001", "-p ": "tcp", "-j ": "REJECT"},
			},
			destChain: "REJECT",
			destIP:    "",
			destPort:  "3001",
			expected:  true,
		},
		"case 3": {
			// Match both dest IP and dest Port
			rules: []iptablestest.Rule{
				{"-d ": "1.2.3.4/32", "--dport ": "80", "-p ": "tcp", "-j ": "KUBE-XLB-GF53O3C2HZEXL2XN"},
			},
			destChain: "KUBE-XLB-GF53O3C2HZEXL2XN",
			destIP:    "1.2.3.4",
			destPort:  "80",
			expected:  true,
		},
		"case 4": {
			// Match dest IP but doesn't match dest Port
			rules: []iptablestest.Rule{
				{"-d ": "1.2.3.4/32", "--dport ": "80", "-p ": "tcp", "-j ": "KUBE-XLB-GF53O3C2HZEXL2XN"},
			},
			destChain: "KUBE-XLB-GF53O3C2HZEXL2XN",
			destIP:    "1.2.3.4",
			destPort:  "8080",
			expected:  false,
		},
		"case 5": {
			// Match dest Port but doesn't match dest IP
			rules: []iptablestest.Rule{
				{"-d ": "1.2.3.4/32", "--dport ": "80", "-p ": "tcp", "-j ": "KUBE-XLB-GF53O3C2HZEXL2XN"},
			},
			destChain: "KUBE-XLB-GF53O3C2HZEXL2XN",
			destIP:    "10.20.30.40",
			destPort:  "80",
			expected:  false,
		},
		"case 6": {
			// Match the 2nd rule(dest IP)
			rules: []iptablestest.Rule{
				{"-d ": "10.20.30.41/32", "-p ": "tcp", "-j ": "REJECT"},
				{"-d ": "1.2.3.4/32", "-p ": "tcp", "-j ": "REJECT"},
				{"--dport ": "3001", "-p ": "tcp", "-j ": "REJECT"},
			},
			destChain: "REJECT",
			destIP:    "1.2.3.4",
			destPort:  "8080",
			expected:  true,
		},
		"case 7": {
			// Match the 2nd rule(dest Port)
			rules: []iptablestest.Rule{
				{"-d ": "10.20.30.41/32", "-p ": "tcp", "-j ": "REJECT"},
				{"--dport ": "3001", "-p ": "tcp", "-j ": "REJECT"},
			},
			destChain: "REJECT",
			destIP:    "1.2.3.4",
			destPort:  "3001",
			expected:  true,
		},
		"case 8": {
			// Match the 1st rule(dest IP)
			rules: []iptablestest.Rule{
				{"-d ": "10.20.30.41/32", "-p ": "tcp", "-j ": "REJECT"},
				{"--dport ": "3001", "-p ": "tcp", "-j ": "REJECT"},
			},
			destChain: "REJECT",
			destIP:    "10.20.30.41",
			destPort:  "8080",
			expected:  true,
		},
		"case 9": {
			rules: []iptablestest.Rule{
				{"-j ": "KUBE-SEP-LWSOSDSHMKPJHHJV"},
			},
			destChain: "KUBE-SEP-LWSOSDSHMKPJHHJV",
			destIP:    "",
			destPort:  "",
			expected:  true,
		},
		"case 10": {
			rules: []iptablestest.Rule{
				{"-j ": "KUBE-SEP-FOO"},
			},
			destChain: "KUBE-SEP-BAR",
			destIP:    "",
			destPort:  "",
			expected:  false,
		},
	}

	for k, tc := range testCases {
		if got := hasJump(tc.rules, tc.destChain, tc.destIP, tc.destPort); got != tc.expected {
			t.Errorf("%v: expected %v, got %v", k, tc.expected, got)
		}
	}
}

func hasDNAT(rules []iptablestest.Rule, endpoint string) bool {
	for _, r := range rules {
		if r[iptablestest.ToDest] == endpoint {
			return true
		}
	}
	return false
}

func errorf(msg string, rules []iptablestest.Rule, t *testing.T) {
	for _, r := range rules {
		t.Logf("%v", r)
	}
	t.Errorf("%v", msg)
}

func TestClusterIPReject(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcName := "svc1"
	svcIP := net.IPv4(10, 20, 30, 41)

	svc := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: svcName}, Port: "80"}
	fp.serviceMap[svc] = newFakeServiceInfo(svc, svcIP, 80, api.ProtocolTCP, false)
	fp.syncProxyRules()

	svcChain := string(servicePortChainName(svc, strings.ToLower(string(api.ProtocolTCP))))
	svcRules := ipt.GetRules(svcChain)
	if len(svcRules) != 0 {
		errorf(fmt.Sprintf("Unexpected rule for chain %v service %v without endpoints", svcChain, svcName), svcRules, t)
	}
	kubeSvcRules := ipt.GetRules(string(kubeServicesChain))
	if !hasJump(kubeSvcRules, iptablestest.Reject, svcIP.String(), "80") {
		errorf(fmt.Sprintf("Failed to find a %v rule for service %v with no endpoints", iptablestest.Reject, svcName), kubeSvcRules, t)
	}
}

func TestClusterIPEndpointsJump(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcName := "svc1"
	svcIP := net.IPv4(10, 20, 30, 41)

	svc := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: svcName}, Port: "80"}
	fp.serviceMap[svc] = newFakeServiceInfo(svc, svcIP, 80, api.ProtocolTCP, true)
	ep := "10.180.0.1:80"
	fp.endpointsMap[svc] = []*endpointsInfo{{ep, false}}

	fp.syncProxyRules()

	svcChain := string(servicePortChainName(svc, strings.ToLower(string(api.ProtocolTCP))))
	epChain := string(servicePortEndpointChainName(svc, strings.ToLower(string(api.ProtocolTCP)), ep))

	kubeSvcRules := ipt.GetRules(string(kubeServicesChain))
	if !hasJump(kubeSvcRules, svcChain, svcIP.String(), "80") {
		errorf(fmt.Sprintf("Failed to find jump from KUBE-SERVICES to %v chain", svcChain), kubeSvcRules, t)
	}

	svcRules := ipt.GetRules(svcChain)
	if !hasJump(svcRules, epChain, "", "") {
		errorf(fmt.Sprintf("Failed to jump to ep chain %v", epChain), svcRules, t)
	}
	epRules := ipt.GetRules(epChain)
	if !hasDNAT(epRules, ep) {
		errorf(fmt.Sprintf("Endpoint chain %v lacks DNAT to %v", epChain, ep), epRules, t)
	}
}

func typeLoadBalancer(svcInfo *serviceInfo) *serviceInfo {
	svcInfo.nodePort = 3001
	svcInfo.loadBalancerStatus = api.LoadBalancerStatus{
		Ingress: []api.LoadBalancerIngress{{IP: "1.2.3.4"}},
	}
	return svcInfo
}

func TestLoadBalancer(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcName := "svc1"
	svcIP := net.IPv4(10, 20, 30, 41)

	svc := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: svcName}, Port: "80"}
	svcInfo := newFakeServiceInfo(svc, svcIP, 80, api.ProtocolTCP, false)
	fp.serviceMap[svc] = typeLoadBalancer(svcInfo)

	ep1 := "10.180.0.1:80"
	fp.endpointsMap[svc] = []*endpointsInfo{{ep1, false}}

	fp.syncProxyRules()

	proto := strings.ToLower(string(api.ProtocolTCP))
	fwChain := string(serviceFirewallChainName(svc, proto))
	svcChain := string(servicePortChainName(svc, strings.ToLower(string(api.ProtocolTCP))))
	//lbChain := string(serviceLBChainName(svc, proto))

	kubeSvcRules := ipt.GetRules(string(kubeServicesChain))
	if !hasJump(kubeSvcRules, fwChain, svcInfo.loadBalancerStatus.Ingress[0].IP, "80") {
		errorf(fmt.Sprintf("Failed to find jump to firewall chain %v", fwChain), kubeSvcRules, t)
	}

	fwRules := ipt.GetRules(fwChain)
	if !hasJump(fwRules, svcChain, "", "") || !hasJump(fwRules, string(KubeMarkMasqChain), "", "") {
		errorf(fmt.Sprintf("Failed to find jump from firewall chain %v to svc chain %v", fwChain, svcChain), fwRules, t)
	}
}

func TestNodePort(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcName := "svc1"
	svcIP := net.IPv4(10, 20, 30, 41)

	svc := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: svcName}, Port: "80"}
	svcInfo := newFakeServiceInfo(svc, svcIP, 80, api.ProtocolTCP, false)
	svcInfo.nodePort = 3001
	fp.serviceMap[svc] = svcInfo

	ep1 := "10.180.0.1:80"
	fp.endpointsMap[svc] = []*endpointsInfo{{ep1, false}}

	fp.syncProxyRules()

	proto := strings.ToLower(string(api.ProtocolTCP))
	svcChain := string(servicePortChainName(svc, strings.ToLower(proto)))

	kubeNodePortRules := ipt.GetRules(string(kubeNodePortsChain))
	if !hasJump(kubeNodePortRules, svcChain, "", fmt.Sprintf("%v", svcInfo.nodePort)) {
		errorf(fmt.Sprintf("Failed to find jump to svc chain %v", svcChain), kubeNodePortRules, t)
	}
}

func TestOnlyLocalLoadBalancing(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	svcName := "svc1"
	svcIP := net.IPv4(10, 20, 30, 41)

	svc := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: svcName}, Port: "80"}
	svcInfo := newFakeServiceInfo(svc, svcIP, 80, api.ProtocolTCP, true)
	fp.serviceMap[svc] = typeLoadBalancer(svcInfo)

	nonLocalEp := "10.180.0.1:80"
	localEp := "10.180.2.1:80"
	fp.endpointsMap[svc] = []*endpointsInfo{{nonLocalEp, false}, {localEp, true}}

	fp.syncProxyRules()

	proto := strings.ToLower(string(api.ProtocolTCP))
	fwChain := string(serviceFirewallChainName(svc, proto))
	lbChain := string(serviceLBChainName(svc, proto))

	nonLocalEpChain := string(servicePortEndpointChainName(svc, strings.ToLower(string(api.ProtocolTCP)), nonLocalEp))
	localEpChain := string(servicePortEndpointChainName(svc, strings.ToLower(string(api.ProtocolTCP)), localEp))

	kubeSvcRules := ipt.GetRules(string(kubeServicesChain))
	if !hasJump(kubeSvcRules, fwChain, svcInfo.loadBalancerStatus.Ingress[0].IP, "") {
		errorf(fmt.Sprintf("Failed to find jump to firewall chain %v", fwChain), kubeSvcRules, t)
	}

	fwRules := ipt.GetRules(fwChain)
	if !hasJump(fwRules, lbChain, "", "") {
		errorf(fmt.Sprintf("Failed to find jump from firewall chain %v to svc chain %v", fwChain, lbChain), fwRules, t)
	}
	if hasJump(fwRules, string(KubeMarkMasqChain), "", "") {
		errorf(fmt.Sprintf("Found jump from fw chain %v to MASQUERADE", fwChain), fwRules, t)
	}

	lbRules := ipt.GetRules(lbChain)
	if hasJump(lbRules, nonLocalEpChain, "", "") {
		errorf(fmt.Sprintf("Found jump from lb chain %v to non-local ep %v", lbChain, nonLocalEp), lbRules, t)
	}
	if !hasJump(lbRules, localEpChain, "", "") {
		errorf(fmt.Sprintf("Didn't find jump from lb chain %v to local ep %v", lbChain, nonLocalEp), lbRules, t)
	}
}

func TestOnlyLocalNodePortsNoClusterCIDR(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	// set cluster CIDR to empty before test
	fp.clusterCIDR = ""
	onlyLocalNodePorts(t, fp, ipt)
}

func TestOnlyLocalNodePorts(t *testing.T) {
	ipt := iptablestest.NewFake()
	fp := NewFakeProxier(ipt)
	onlyLocalNodePorts(t, fp, ipt)
}

func onlyLocalNodePorts(t *testing.T, fp *Proxier, ipt *iptablestest.FakeIPTables) {
	shouldLBTOSVCRuleExist := len(fp.clusterCIDR) > 0
	svcName := "svc1"
	svcIP := net.IPv4(10, 20, 30, 41)

	svc := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "ns1", Name: svcName}, Port: "80"}
	svcInfo := newFakeServiceInfo(svc, svcIP, 80, api.ProtocolTCP, true)
	svcInfo.nodePort = 3001
	fp.serviceMap[svc] = svcInfo

	nonLocalEp := "10.180.0.1:80"
	localEp := "10.180.2.1:80"
	fp.endpointsMap[svc] = []*endpointsInfo{{nonLocalEp, false}, {localEp, true}}

	fp.syncProxyRules()

	proto := strings.ToLower(string(api.ProtocolTCP))
	lbChain := string(serviceLBChainName(svc, proto))

	nonLocalEpChain := string(servicePortEndpointChainName(svc, strings.ToLower(string(api.ProtocolTCP)), nonLocalEp))
	localEpChain := string(servicePortEndpointChainName(svc, strings.ToLower(string(api.ProtocolTCP)), localEp))

	kubeNodePortRules := ipt.GetRules(string(kubeNodePortsChain))
	if !hasJump(kubeNodePortRules, lbChain, "", fmt.Sprintf("%v", svcInfo.nodePort)) {
		errorf(fmt.Sprintf("Failed to find jump to lb chain %v", lbChain), kubeNodePortRules, t)
	}

	svcChain := string(servicePortChainName(svc, strings.ToLower(string(api.ProtocolTCP))))
	lbRules := ipt.GetRules(lbChain)
	if hasJump(lbRules, nonLocalEpChain, "", "") {
		errorf(fmt.Sprintf("Found jump from lb chain %v to non-local ep %v", lbChain, nonLocalEp), lbRules, t)
	}
	if hasJump(lbRules, svcChain, "", "") != shouldLBTOSVCRuleExist {
		prefix := "Did not find "
		if !shouldLBTOSVCRuleExist {
			prefix = "Found "
		}
		errorf(fmt.Sprintf("%s jump from lb chain %v to svc %v", prefix, lbChain, svcChain), lbRules, t)
	}
	if !hasJump(lbRules, localEpChain, "", "") {
		errorf(fmt.Sprintf("Didn't find jump from lb chain %v to local ep %v", lbChain, nonLocalEp), lbRules, t)
	}
}

func makeTestService(namespace, name string, svcFunc func(*api.Service)) api.Service {
	svc := api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec:   api.ServiceSpec{},
		Status: api.ServiceStatus{},
	}
	svcFunc(&svc)
	return svc
}

func addTestPort(array []api.ServicePort, name string, protocol api.Protocol, port, nodeport int32, targetPort int) []api.ServicePort {
	svcPort := api.ServicePort{
		Name:       name,
		Protocol:   protocol,
		Port:       port,
		NodePort:   nodeport,
		TargetPort: intstr.FromInt(targetPort),
	}
	return append(array, svcPort)
}

func TestBuildServiceMapAddRemove(t *testing.T) {
	services := []api.Service{
		makeTestService("somewhere-else", "cluster-ip", func(svc *api.Service) {
			svc.Spec.Type = api.ServiceTypeClusterIP
			svc.Spec.ClusterIP = "172.16.55.4"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "something", "UDP", 1234, 4321, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "somethingelse", "UDP", 1235, 5321, 0)
		}),
		makeTestService("somewhere-else", "node-port", func(svc *api.Service) {
			svc.Spec.Type = api.ServiceTypeNodePort
			svc.Spec.ClusterIP = "172.16.55.10"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "blahblah", "UDP", 345, 678, 0)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "moreblahblah", "TCP", 344, 677, 0)
		}),
		makeTestService("somewhere", "load-balancer", func(svc *api.Service) {
			svc.Spec.Type = api.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = "172.16.55.11"
			svc.Spec.LoadBalancerIP = "5.6.7.8"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "foobar", "UDP", 8675, 30061, 7000)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "baz", "UDP", 8676, 30062, 7001)
			svc.Status.LoadBalancer = api.LoadBalancerStatus{
				Ingress: []api.LoadBalancerIngress{
					{IP: "10.1.2.4"},
				},
			}
		}),
		makeTestService("somewhere", "only-local-load-balancer", func(svc *api.Service) {
			svc.ObjectMeta.Annotations = map[string]string{
				service.BetaAnnotationExternalTraffic:     service.AnnotationValueExternalTrafficLocal,
				service.BetaAnnotationHealthCheckNodePort: "345",
			}
			svc.Spec.Type = api.ServiceTypeLoadBalancer
			svc.Spec.ClusterIP = "172.16.55.12"
			svc.Spec.LoadBalancerIP = "5.6.7.8"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "foobar2", "UDP", 8677, 30063, 7002)
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "baz", "UDP", 8678, 30064, 7003)
			svc.Status.LoadBalancer = api.LoadBalancerStatus{
				Ingress: []api.LoadBalancerIngress{
					{IP: "10.1.2.3"},
				},
			}
		}),
	}

	serviceMap, hcAdd, hcDel, staleUDPServices := buildServiceMap(services, make(proxyServiceMap))
	if len(serviceMap) != 8 {
		t.Errorf("expected service map length 8, got %v", serviceMap)
	}

	// The only-local-loadbalancer ones get added
	if len(hcAdd) != 2 {
		t.Errorf("expected healthcheck add length 2, got %v", hcAdd)
	} else {
		for _, hc := range hcAdd {
			if hc.namespace.Namespace != "somewhere" || hc.namespace.Name != "only-local-load-balancer" {
				t.Errorf("unexpected healthcheck listener added: %v", hc)
			}
		}
	}

	// All the rest get deleted
	if len(hcDel) != 6 {
		t.Errorf("expected healthcheck del length 6, got %v", hcDel)
	} else {
		for _, hc := range hcDel {
			if hc.namespace.Namespace == "somewhere" && hc.namespace.Name == "only-local-load-balancer" {
				t.Errorf("unexpected healthcheck listener deleted: %v", hc)
			}
		}
	}

	if len(staleUDPServices) != 0 {
		// Services only added, so nothing stale yet
		t.Errorf("expected stale UDP services length 0, got %d", len(staleUDPServices))
	}

	// Remove some stuff
	services = []api.Service{services[0]}
	services[0].Spec.Ports = []api.ServicePort{services[0].Spec.Ports[1]}
	serviceMap, hcAdd, hcDel, staleUDPServices = buildServiceMap(services, serviceMap)
	if len(serviceMap) != 1 {
		t.Errorf("expected service map length 1, got %v", serviceMap)
	}

	if len(hcAdd) != 0 {
		t.Errorf("expected healthcheck add length 1, got %v", hcAdd)
	}

	// The only OnlyLocal annotation was removed above, so we expect a delete now.
	// FIXME: Since the BetaAnnotationHealthCheckNodePort is the same for all
	// ServicePorts, we'll get one delete per ServicePort, even though they all
	// contain the same information
	if len(hcDel) != 2 {
		t.Errorf("expected healthcheck del length 2, got %v", hcDel)
	} else {
		for _, hc := range hcDel {
			if hc.namespace.Namespace != "somewhere" || hc.namespace.Name != "only-local-load-balancer" {
				t.Errorf("unexpected healthcheck listener deleted: %v", hc)
			}
		}
	}

	// All services but one were deleted. While you'd expect only the ClusterIPs
	// from the three deleted services here, we still have the ClusterIP for
	// the not-deleted service, because one of it's ServicePorts was deleted.
	expectedStaleUDPServices := []string{"172.16.55.10", "172.16.55.4", "172.16.55.11", "172.16.55.12"}
	if len(staleUDPServices) != len(expectedStaleUDPServices) {
		t.Errorf("expected stale UDP services length %d, got %v", len(expectedStaleUDPServices), staleUDPServices.List())
	}
	for _, ip := range expectedStaleUDPServices {
		if !staleUDPServices.Has(ip) {
			t.Errorf("expected stale UDP service service %s", ip)
		}
	}
}

func TestBuildServiceMapServiceHeadless(t *testing.T) {
	services := []api.Service{
		makeTestService("somewhere-else", "headless", func(svc *api.Service) {
			svc.Spec.Type = api.ServiceTypeClusterIP
			svc.Spec.ClusterIP = api.ClusterIPNone
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "rpc", "UDP", 1234, 0, 0)
		}),
	}

	// Headless service should be ignored
	serviceMap, hcAdd, hcDel, staleUDPServices := buildServiceMap(services, make(proxyServiceMap))
	if len(serviceMap) != 0 {
		t.Errorf("expected service map length 0, got %d", len(serviceMap))
	}

	// No proxied services, so no healthchecks
	if len(hcAdd) != 0 {
		t.Errorf("expected healthcheck add length 0, got %d", len(hcAdd))
	}
	if len(hcDel) != 0 {
		t.Errorf("expected healthcheck del length 0, got %d", len(hcDel))
	}

	if len(staleUDPServices) != 0 {
		t.Errorf("expected stale UDP services length 0, got %d", len(staleUDPServices))
	}
}

func TestBuildServiceMapServiceTypeExternalName(t *testing.T) {
	services := []api.Service{
		makeTestService("somewhere-else", "external-name", func(svc *api.Service) {
			svc.Spec.Type = api.ServiceTypeExternalName
			svc.Spec.ClusterIP = "172.16.55.4" // Should be ignored
			svc.Spec.ExternalName = "foo2.bar.com"
			svc.Spec.Ports = addTestPort(svc.Spec.Ports, "blah", "UDP", 1235, 5321, 0)
		}),
	}

	serviceMap, hcAdd, hcDel, staleUDPServices := buildServiceMap(services, make(proxyServiceMap))
	if len(serviceMap) != 0 {
		t.Errorf("expected service map length 0, got %v", serviceMap)
	}
	// No proxied services, so no healthchecks
	if len(hcAdd) != 0 {
		t.Errorf("expected healthcheck add length 0, got %v", hcAdd)
	}
	if len(hcDel) != 0 {
		t.Errorf("expected healthcheck del length 0, got %v", hcDel)
	}
	if len(staleUDPServices) != 0 {
		t.Errorf("expected stale UDP services length 0, got %v", staleUDPServices)
	}
}

// TODO(thockin): add *more* tests for syncProxyRules() or break it down further and test the pieces.
