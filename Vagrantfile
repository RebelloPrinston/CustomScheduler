# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

# Require a recent version of vagrant otherwise some have reported errors setting host names on boxes
Vagrant.require_version ">= 1.6.2"

if ARGV.first == "up" && ENV['USING_KUBE_SCRIPTS'] != 'true'
  raise Vagrant::Errors::VagrantError.new, <<END
Calling 'vagrant up' directly is not supported.  Instead, please run the following:

  export KUBERNETES_PROVIDER=vagrant
  ./cluster/kube-up.sh
END
end

# The number of minions to provision
$num_minion = (ENV['NUM_MINIONS'] || 1).to_i

# ip configuration
$master_ip = ENV['MASTER_IP']
$minion_ip_base = ENV['MINION_IP_BASE'] || ""
$minion_ips = $num_minion.times.collect { |n| $minion_ip_base + "#{n+3}" }

# Determine the OS platform to use
$kube_os = ENV['KUBERNETES_OS'] || "fedora"

# To override the vagrant provider, use (e.g.):
#   DEFAULT_VAGRANT_PROVIDER=... .../cluster/kube-up.sh
# To override the box, use (e.g.):
#   KUBERNETES_BOX_NAME=... .../cluster/kube-up.sh
# You can overried both (e.g.):
#   DEFAULT_VAGRANT_PROVIDER=... KUBERNETES_BOX_NAME=... .../cluster/kube-up.sh
# You can specify a box version:
#   KUBERNETES_BOX_NAME=... KUBERNETES_BOX_VERSION=... .../cluster/kube-up.sh
# If you want to specify the location for the box instead of the version,
# add (e.g.):
#   KUBERNETES_BOX_NAME=... KUBERNETES_BOX_URL=... .../cluster/kube-up.sh
# KUBERNETES_BOX_URL and KUBERNETES_BOX_VERSION will be ignored unless
# KUBERNETES_BOX_NAME is set

# Default OS platform to provider/box information
$kube_provider_boxes = {
  :parallels => {
    'fedora' => {
      # :box_url and :box_version are optional (and mutually exclusive);
      # if :box_url is omitted the box will be retrieved by :box_name (and
      # :box_version if provided) from
      # http://atlas.hashicorp.com/boxes/search (formerly
      # http://vagrantcloud.com/); this allows you override :box_name with
      # your own value so long as you provide :box_url; for example, the
      # "official" name of this box is
      # "rickard-von-essen/opscode_fedora-20", but by providing the URL
      # and our own name, we make it appear as yet another provider under
      # the "kube-fedora20" box
      :box_name => 'kube-fedora20',
      :box_url => 'https://atlas.hashicorp.com/rickard-von-essen/boxes/opscode_fedora-20/versions/0.4.0/providers/parallels.box'
    }
  },
  :virtualbox => {
    'fedora' => {
      :box_name => 'kube-fedora20',
      :box_url => 'http://opscode-vm-bento.s3.amazonaws.com/vagrant/virtualbox/opscode_fedora-20_chef-provisionerless.box'
    }
  },
  :vmware_desktop => {
    'fedora' => {
      :box_name => 'kube-fedora20',
      :box_url => 'http://opscode-vm-bento.s3.amazonaws.com/vagrant/vmware/opscode_fedora-20-i386_chef-provisionerless.box'
    }
  }
}

# This stuff is cargo-culted from http://www.stefanwrobel.com/how-to-make-vagrant-performance-not-suck
# Give access to half of all cpu cores on the host. We divide by 2 as we assume
# that users are running with hyperthreads.
host = RbConfig::CONFIG['host_os']
if host =~ /darwin/
  $vm_cpus = (`sysctl -n hw.ncpu`.to_i/2.0).ceil
elsif host =~ /linux/
  $vm_cpus = (`nproc`.to_i/2.0).ceil
else # sorry Windows folks, I can't help you
  $vm_cpus = 2
end

# Give VM 1024MB of RAM by default
# In Fedora VM, tmpfs device is mapped to /tmp.  tmpfs is given 50% of RAM allocation.
# When doing Salt provisioning, we copy approximately 200MB of content in /tmp before anything else happens.
# This causes problems if anything else was in /tmp or the other directories that are bound to tmpfs device (i.e /run, etc.)
$vm_mem = (ENV['KUBERNETES_MEMORY'] || 1024).to_i

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  def setvmboxandurl(config, provider)
    if ENV['KUBERNETES_BOX_NAME']
      config.vm.box = ENV['KUBERNETES_BOX_NAME']

      if ENV['KUBERNETES_BOX_URL']
        config.vm.box_url = ENV['KUBERNETES_BOX_URL']
      end

      if ENV['KUBERNETES_BOX_VERSION']
        config.vm.box_version = ENV['KUBERNETES_BOX_VERSION']
      end
    else
      config.vm.box = $kube_provider_boxes[provider][$kube_os][:box_name]

      if $kube_provider_boxes[provider][$kube_os][:box_url]
        config.vm.box_url = $kube_provider_boxes[provider][$kube_os][:box_url]
      end

      if $kube_provider_boxes[provider][$kube_os][:box_version]
        config.vm.box_version = $kube_provider_boxes[provider][$kube_os][:box_version]
      end
    end
  end

  def customize_vm(config)
    # Try VMWare Fusion first (see
    # https://docs.vagrantup.com/v2/providers/basic_usage.html)
    config.vm.provider :vmware_fusion do |v, override|
      setvmboxandurl(override, :vmware_desktop)
      v.vmx['memsize'] = $vm_mem
      v.vmx['numvcpus'] = $vm_cpus
    end

    # Then try VMWare Workstation
    config.vm.provider :vmware_workstation do |v, override|
      setvmboxandurl(override, :vmware_desktop)
      v.vmx['memsize'] = $vm_mem
      v.vmx['numvcpus'] = $vm_cpus
    end

    # Then try Parallels
    config.vm.provider :parallels do |v, override|
      setvmboxandurl(override, :parallels)
      v.memory = $vm_mem # v.customize ['set', :id, '--memsize', $vm_mem]
      v.cpus = $vm_cpus # v.customize ['set', :id, '--cpus', $vm_cpus]

      # Don't attempt to update the Parallels tools on the image (this can
      # be done manually if necessary)
      v.update_guest_tools = false # v.customize ['set', :id, '--tools-autoupdate', 'off']

      # Set up Parallels folder sharing to behave like VirtualBox (i.e.,
      # mount the current directory as /vagrant and that's it)
      v.customize ['set', :id, '--shf-guest', 'off']
      v.customize ['set', :id, '--shf-guest-automount', 'off']
      v.customize ['set', :id, '--shf-host', 'on']
    end

    # Finally, fall back to VirtualBox
    config.vm.provider :virtualbox do |v, override|
      setvmboxandurl(override, :virtualbox)
      v.memory = $vm_mem # v.customize ["modifyvm", :id, "--memory", $vm_mem]
      v.cpus = $vm_cpus # v.customize ["modifyvm", :id, "--cpus", $vm_cpus]

      # Use faster paravirtualized networking
      v.customize ["modifyvm", :id, "--nictype1", "virtio"]
      v.customize ["modifyvm", :id, "--nictype2", "virtio"]
    end
  end

  # Kubernetes master
  config.vm.define "master" do |c|
    customize_vm c
    if ENV['KUBE_TEMP'] then
      script = "#{ENV['KUBE_TEMP']}/master-start.sh"
      c.vm.provision "shell", run: "always", path: script
    end
    c.vm.network "private_network", ip: "#{$master_ip}"
    c.vm.hostname = ENV['MASTER_NAME']
  end

  # Kubernetes minion
  $num_minion.times do |n|
    config.vm.define "minion-#{n+1}" do |minion|
      customize_vm minion

      minion_index = n+1
      minion_ip = $minion_ips[n]
      if ENV['KUBE_TEMP'] then
        script = "#{ENV['KUBE_TEMP']}/minion-start-#{n}.sh"
        minion.vm.provision "shell", run: "always", path: script
      end
      minion.vm.network "private_network", ip: "#{minion_ip}"
      minion.vm.hostname = "#{ENV['INSTANCE_PREFIX']}-minion-#{minion_index}"
    end
  end
end
