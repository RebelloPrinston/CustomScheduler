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

// Package upgrade holds the common phases for 'kubeadm upgrade'.
package upgrade

import (
	"context"
	"fmt"
	"io"

	"github.com/pkg/errors"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientset "k8s.io/client-go/kubernetes"

	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	"k8s.io/kubernetes/cmd/kubeadm/app/cmd/options"
	"k8s.io/kubernetes/cmd/kubeadm/app/cmd/phases/workflow"
	"k8s.io/kubernetes/cmd/kubeadm/app/constants"
	dnsaddon "k8s.io/kubernetes/cmd/kubeadm/app/phases/addons/dns"
	proxyaddon "k8s.io/kubernetes/cmd/kubeadm/app/phases/addons/proxy"
	"k8s.io/kubernetes/cmd/kubeadm/app/phases/upgrade"
)

// NewAddonPhase returns a new addon phase.
func NewAddonPhase() workflow.Phase {
	return workflow.Phase{
		Name:  "addon",
		Short: "Upgrade the default kubeadm addons",
		Phases: []workflow.Phase{
			{
				Name:           "all",
				Short:          "Upgrade all the addons",
				InheritFlags:   getAddonPhaseFlags("all"),
				RunAllSiblings: true,
			},
			{
				Name:         "coredns",
				Short:        "Upgrade the CoreDNS addon",
				InheritFlags: getAddonPhaseFlags("coredns"),
				Run:          runCoreDNSAddon,
			},
			{
				Name:         "kube-proxy",
				Short:        "Upgrade the kube-proxy addon",
				InheritFlags: getAddonPhaseFlags("kube-proxy"),
				Run:          runKubeProxyAddon,
			},
		},
	}
}

func shouldUpgradeAddons(client clientset.Interface, cfg *kubeadmapi.InitConfiguration, out io.Writer) (bool, error) {
	nodeSelector := labels.SelectorFromSet(labels.Set(map[string]string{
		constants.LabelNodeRoleControlPlane: "",
		v1.LabelHostname:                    cfg.NodeRegistration.Name,
	}))
	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
		LabelSelector: nodeSelector.String(),
	})
	if err != nil {
		return false, errors.Wrapf(err, "failed to get Node %v from cluster", cfg.NodeRegistration.Name)
	}
	if len(nodes.Items) == 0 {
		fmt.Println("[upgrade/control-plane] Skipping phase. Not a control plane node.")
		return false, nil
	}

	unupgradedControlPlanes, err := upgrade.UnupgradedControlPlaneInstances(client, cfg.NodeRegistration.Name)
	if err != nil {
		return false, errors.Wrapf(err, "failed to determine whether all the control plane instances have been upgraded")
	}
	if len(unupgradedControlPlanes) > 0 {
		fmt.Fprintf(out, "[upgrade/addon] Skipping upgrade of addons because control plane instances %v have not been upgraded\n", unupgradedControlPlanes)
		return false, nil
	}
	return true, nil
}

func getInitData(c workflow.RunData) (*kubeadmapi.InitConfiguration, clientset.Interface, string, io.Writer, bool, error) {
	data, ok := c.(Data)
	if !ok {
		return nil, nil, "", nil, false, errors.New("addon phase invoked with an invalid data struct")
	}
	return data.InitCfg(), data.Client(), data.PatchesDir(), data.OutputWriter(), data.DryRun(), nil
}

// runCoreDNSAddon upgrades the CoreDNS addon.
func runCoreDNSAddon(c workflow.RunData) error {
	cfg, client, patchesDir, out, dryRun, err := getInitData(c)
	if err != nil {
		return err
	}

	shouldUpgradeAddons, err := shouldUpgradeAddons(client, cfg, out)
	if err != nil {
		return err
	}
	if !shouldUpgradeAddons {
		return nil
	}

	if err := dnsaddon.EnsureDNSAddon(&cfg.ClusterConfiguration, client, patchesDir, out, dryRun); err != nil {
		return err
	}

	return nil
}

// runKubeProxyAddon upgrades the kube-proxy addon.
func runKubeProxyAddon(c workflow.RunData) error {
	cfg, client, _, out, dryRun, err := getInitData(c)
	if err != nil {
		return err
	}

	shouldUpgradeAddons, err := shouldUpgradeAddons(client, cfg, out)
	if err != nil {
		return err
	}
	if !shouldUpgradeAddons {
		return nil
	}

	if err := proxyaddon.EnsureProxyAddon(&cfg.ClusterConfiguration, &cfg.LocalAPIEndpoint, client, out, dryRun); err != nil {
		return err
	}

	return nil
}

func getAddonPhaseFlags(name string) []string {
	flags := []string{
		options.CfgPath,
		options.KubeconfigPath,
		options.DryRun,
	}
	if name == "all" || name == "coredns" {
		flags = append(flags,
			options.Patches,
		)
	}
	return flags
}
