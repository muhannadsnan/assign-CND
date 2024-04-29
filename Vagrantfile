
Vagrant.configure("2") do |config|
  config.vm.box = "boxen/ubuntu-22.04-x86_64"
  # config.vbguest.auto_update = false
  config.vm.network "forwarded_port", guest: 80, host: 80
  config.vm.network "private_network", ip: "192.168.88.8"
  config.vm.synced_folder "code", "/code/"
  config.ssh.insert_key = false
  # config.ssh.private_key_path = "~/.ssh/id_rsa.pub"
  config.ssh.private_key_path = "~/.vagrant.d/insecure_private_key"

  config.ssh.forward_agent = true

  config.vm.provider "virtualbox" do |vb|
     vb.memory = "2048"
  end

  
end
