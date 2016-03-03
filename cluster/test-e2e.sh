#!/usr/bin/env bash

# Copyright 2014 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Tests a running Kubernetes cluster.
# TODO: move code from hack/ginkgo-e2e.sh to here

set -o errexit
set -o nounset
set -o pipefail

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/..
source "${KUBE_ROOT}/cluster/kube-env.sh"

echo "Testing cluster with provider: ${KUBERNETES_PROVIDER}" 1>&2

TEST_ARGS="$@"

echo "Running e2e tests:" 1>&2
echo "./hack/ginkgo-e2e.sh ${TEST_ARGS}" 1>&2
exec "${KUBE_ROOT}/hack/ginkgo-e2e.sh" "$@"
