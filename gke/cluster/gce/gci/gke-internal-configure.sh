#!/bin/bash
NPD_CUSTOM_PLUGINS_VERSION="${NPD_CUSTOM_PLUGINS_VERSION:-v1.0.3}"
NPD_CUSTOM_PLUGINS_TAR_HASH="${NPD_CUSTOM_PLUGINS_TAR_HASH:-bfc36ffa3e678935e8558de5cb78897f958c7aa0c36b58eb4dbadb15aa0a8be760275b98318a3165dd3774f16c32a76c63605d0657eeab83cec135c64369821a}"
NPD_CUSTOM_PLUGINS_RELEASE_PATH="${NPD_CUSTOM_PLUGINS_RELEASE_PATH:-https://storage.googleapis.com/gke-release}"

M4A_APPARMOR_PROFILE_HASH="${M4A_APPARMOR_PROFILE_HASH:-cd84b52e756bee90b4a26612b372519ebf942bb3b6145d1928d3c1ae0faa4a17ea040f3e5f0429df9193dfcf84364d6a4ac56ebefb70420ae12579be5c5b5756}"
M4A_APPARMOR_RELEASE_PATH="${M4A_APPARMOR_RELEASE_PATH:-https://storage.googleapis.com/anthos-migrate-release}"
# Install node problem detector custom plugins.
function install-npd-custom-plugins {
  local -r version="${NPD_CUSTOM_PLUGINS_VERSION}"
  local -r hash="${NPD_CUSTOM_PLUGINS_TAR_HASH}"
  local -r release_path="${NPD_CUSTOM_PLUGINS_RELEASE_PATH}"
  local -r tar="npd-custom-plugins-${version}.tar.gz"

  echo "Downloading ${tar}."
  download-or-bust "${hash}" "${release_path}/npd-custom-plugins/${version}/${tar}"
  local -r dir="${KUBE_HOME}/npd-custom-plugins"
  mkdir -p "${dir}"
  tar xzf "${KUBE_HOME}/${tar}" -C "${dir}" --overwrite
}

function install-m4a-apparmor-profile {
  local -r hash="${M4A_APPARMOR_PROFILE_HASH}"
  local -r release_path="${M4A_APPARMOR_RELEASE_PATH}"
  local -r profile="m4a-apparmor-profile"

  if type apparmor_parser; then
    echo "Downloading ${profile}."
    download-or-bust "${hash}" "${release_path}/artifacts/${profile}"

    sudo apparmor_parser --remove ${KUBE_HOME}/${profile} || true
    sudo apparmor_parser ${KUBE_HOME}/${profile}
  else
    echo "No apparmor_parser found, cannot install M4A apparmor profile"
  fi
}
