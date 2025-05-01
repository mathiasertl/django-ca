BOX_BASE = "ubuntu/jammy64"
ENVIRONMENT = {
    INSTALL_BASE: '/opt/django-ca/src/django-ca',
    CA_DEFAULT_HOSTNAME: ENV.fetch('CA_DEFAULT_HOSTNAME', 'django-ca.internal'),
    USE_UV: ENV.fetch('USE_UV', '1'),
    UV_CONCURRENT_BUILDS: '1',
    UV_CONCURRENT_INSTALLS: '1',
    DJANGO_CA_VERSION: `python -m setuptools_scm`.strip,
}

Vagrant.configure("2") do |config|
  config.vm.provision "shell", path: "vagrant/common.sh", reboot: true

  config.vm.define "broker" do |broker|
    broker.vm.box = BOX_BASE
    broker.vm.hostname = "broker"
    broker.vm.network "private_network", ip: "192.168.56.10"

    broker.vm.provider "virtualbox" do |vb|
      vb.memory = "512"
    end

    broker.vm.provision "shell", path: "vagrant/broker.sh"
  end

  config.vm.define "db" do |db|
    db.vm.box = BOX_BASE
    db.vm.hostname = "db"
    db.vm.network "private_network", ip: "192.168.56.11"

    db.vm.provider "virtualbox" do |vb|
      vb.memory = "512"
    end

    db.vm.provision "shell", path: "vagrant/db.sh"
  end

  config.vm.define "cache" do |cache|
    cache.vm.box = BOX_BASE
    cache.vm.hostname = "cache"
    cache.vm.network "private_network", ip: "192.168.56.12"

    config.vm.provider "virtualbox" do |vb|
      vb.memory = "512"
    end

    cache.vm.provision "shell", path: "vagrant/cache.sh"
  end

  config.vm.define "backend" do |backend|
    backend.vm.box = BOX_BASE
    backend.vm.hostname = "backend"
    backend.vm.network "private_network", ip: "192.168.56.13"

    backend.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
    end

    backend.vm.provision "shell", path: "vagrant/common-django-ca.sh", env: ENVIRONMENT
    backend.vm.provision "shell", path: "vagrant/backend.sh", env: ENVIRONMENT
  end

  config.vm.define "frontend" do |frontend|
    frontend.vm.box = BOX_BASE
    frontend.vm.hostname = "frontend"
    frontend.vm.network "private_network", ip: "192.168.56.14"

    frontend.vm.provider "virtualbox" do |vb|
      vb.memory = "1024"
    end

    frontend.vm.provision "shell", path: "vagrant/common-django-ca.sh", env: ENVIRONMENT
    frontend.vm.provision "shell", path: "vagrant/frontend.sh", env: ENVIRONMENT
  end
end
