
<!--toc:start-->
- [mofos](#mofos)
  - [Concept](#concept)
  - [Installation](#installation)
  - [Configure the host](#configure-the-host)
    - [QEMU/KVM system session](#qemukvm-system-session)
    - [Security considerations](#security-considerations)
  - [Mofos configuration](#mofos-configuration)
  - [Install a template](#install-a-template)
    - [Configure the firewall](#configure-the-firewall)
    - [Install](#install)
    - [Import](#import)
  - [Create the upper layer empty disk](#create-the-upper-layer-empty-disk)
  - [Create a virtual machine](#create-a-virtual-machine)
  - [Customization](#customization)
    - [Template - hook install](#template-hook-install)
    - [Virtual machine - hook new](#virtual-machine-hook-new)
    - [Virtual machine - hook start](#virtual-machine-hook-start)
  - [Features](#features)
    - [Setup notification when starting or stopping VM](#setup-notification-when-starting-or-stopping-vm)
    - [Clipboard](#clipboard)
    - [Setup routing between machines](#setup-routing-between-machines)
    - [Setup tunneling through pentest boxes](#setup-tunneling-through-pentest-boxes)
    - [USB management](#usb-management)
    - [PCI devices management](#pci-devices-management)
    - [Shared folders](#shared-folders)
  - [Windows machines](#windows-machines)
  - [Autocompletion](#autocompletion)
  - [IP addresses overlap](#ip-addresses-overlap)
<!--toc:end-->

# mofos

Mofos is a tool designed to create, run, and manage virtual machines. It leverages Libvirt/QEMU/KVM, and Python, making it compatible with any Linux distribution. Heavily inspired by Qubes OS (https://www.qubes-os.org/), Mofos aims to replicate many of its features.

The tool has been extensively tested on Debian with Debian-based virtual machines. While other Linux distributions are expected to work, some additional configuration may be necessary. More details to be added.

Mofos provides a range of features focused on securely managing virtual machines, including:
- Seamless window integration using Xpra.
- A clipboard system that enables sending and receiving clipboard content between the host and virtual machines.
- SSH communication with virtual machines.
- Default network restrictions, with flexible options to route or tunnel traffic from one virtual machine through others or remote servers.

## Concept

A mofos machine consists of two disks combined using overlayfs. The first disk, known as the lower layer, is a read-only template disk, while the second disk stores all the changes made by the virtual machine. This template disk is shared across multiple virtual machines. As a result, creating a new virtual machine only requires cloning an empty disk that’s already partitioned to hold the modified data. This approach ensures that new virtual machines can be created quickly, while allowing the template to be updated independently. Any updates to the template will take effect for dependent virtual machines upon their next reboot.


## Installation

Depending on the Linux distribution, the Makefile can be utilized to either generate a `deb` package or install the files directly.

```
$ make deb
# apt install ./mofos-VERSION.deb
```

During the `apt` installation, various settings will be prompted. The default options can generally be accepted. The only setting that requires attention is the subnet address used by the mofos libvirt network (default: `192.168.90.0/24`).

OR 

Install the following dependancies:
- libvirt
- make
- python3-click
- python3-click-completion
- python3-colorama
- python3-lxml
- python3-prettytable
- python3-pyroute2
- python3-tqdm
- socat
- sudo
- virt-install
- virt-manager
- xpra

```
# make local_install
# make configure
```

## Configure the host

### QEMU/KVM system session

Mofos uses the QEMU/KVM system session, so to allow the virsh command to access virtual machines and related resources, set the environment variable `LIBVIRT_DEFAULT_URI` to `qemu:///system`:

```console
export LIBVIRT_DEFAULT_URI=qemu:///system
```

### Security considerations

Using QEMU/KVM system sessions improves isolation between the host and guest virtual machines by running qemu instances under a dedicated user (`libvirt-qemu`) and applying specific security profiles to each instance.

However, by default, regular users cannot interact with the `libvirtd` system socket to manage machines, networks, and other resources. To gain access, users must either be members of the libvirt Unix group or use sudo. Historically, local privilege escalation vulnerabilities have exploited membership in the libvirt group to obtain root privileges.

To mitigate these risks, this repository provides a strengthened AppArmor profile for the `libvirtd` process on systems using AppArmor. This profile significantly restricts where `libvirtd` can write files and which programs it can execute.

Additionally, `polkit` rules are included to further control the actions permitted for members of the `libvirt` group.

Note that the AppArmor profiles are packaged in the `deb` package but are not installed by the Makefile’s `install_files` target and therefore must be installed separately.

## Mofos configuration

Mofos requires a configuration file located at `$HOME/.config/mofos/config.toml` with minimal settings to function correctly. A minimal example configuration can be found at `/usr/share/mofos/config.minimal.toml`, while a more comprehensive configuration is documented in `/usr/share/mofos/config.sample.toml`.

The following error indicates that the configuration file was not found:

```
[-] Copy the sample configuration file from /usr/share/mofos/config.minimal.toml to ~/.config/mofos/config.toml
```

The following error indicates that the current user is not a member of the libvirt group:

```
[-] libvirtError("authentication unavailable: no polkit agent available to authenticate action 'org.libvirt.unix.manage'")
```

The key configuration settings to customize in the configuration files are as follows:
- key (path): The SSH private key file used to access virtual machines. It is recommended to create a dedicated key for this purpose.
- user (string): The username for SSH access to the virtual machines.
- root_password (hashed value): The hashed root password to be set during the installation of a new template.
- root_ssh_pubkey (string): The public SSH key to be installed in the root user’s directory during template installation.

Additionally, the following parameters must be configured for template installation:
- ntp
- dns (optional if a proxy is provided)
- proxy

## Install a template

### Configure the firewall

Since the installation process relies on PXE netboot, an active internet connection is required. The following firewall rules should be configured:

```
sysctl net.ipv4.ip_forward=1
iptables -t nat -I POSTROUTING -s 192.168.90.0/24 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 192.168.91.0/24 -j MASQUERADE
```

Or with nftables:

```
sysctl net.ipv4.ip_forward=1
nft insert inet nat postrouting iifname "install-*" masquerade
nft insert inet nat postrouting iifname "mof0" masquerade
```

When the `ip_forward` parameter is set to 1, the FORWARD chain should be configured to prevent other devices on the network from using the host as a router.

Overall, the following rules are recommended:

```
iptables -I INPUT -i mof0 -p udp --sport 68 --dport 67 -j ACCEPT -m comment --comment "mofos dhcp"
iptables -I INPUT -i mof0 -p udp --dport 69 -j ACCEPT -m comment --comment "mofos tftp"
iptables -I OUTPUT -o mof0 -j ACCEPT -m comment --comment "host -> mofos"
iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD -i mof0 -j ACCEPT -m comment --comment "mofos ->"
iptables -t nat -I POSTROUTING -s 192.168.90.0/24 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 192.168.91.0/24 -j MASQUERADE
```

Or with `nftables`:

```
table inet filter {
    chain input {
      iifname "install-*" ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept comment "mofos dhcp"
      iifname "install-*" udp dport 69 accept comment "mofos tftp"
    }

    chain forward {
      ct state established,related accept;
      ct state invalid drop;
      iifname "mof0" counter accept
      iifname "install-*" counter accept
    }

    chain output {
      oifname "mof0" counter accept
    }
}
table ip nat {
    chain postrouting {
      iifname "mof0" masquerade
      iifname "install-*" masquerade
    }
}
```

It is recommended to restrict masquerade and forwarding rules based on your specific needs, to prevent mofos virtual machines from accessing the entire host network.

Isolation between virtual machines is automatically enforced by a libvirt hook, which requires nft to function properly.


### Install

The first step is to build the initial layer: the template. By default, Mofos can install a Debian 12–based template.

```
mofos template create debian-template
```

Note: For every command, the `--debug` option can be used to obtain detailed technical information in case of unexpected behavior. Specifically for this command, the `--debug` flag also forces a graphical window to display the installation progress. Alternatively, the installation can be monitored using `virt-manager.`

Currently, only the Debian 12 template is supported for installation. The Python dictionary below specifies the installation image to be used:

```python
NETBOOT = {
    "debian-stable-amd64": {
        "variant": "debian11",
        "url": "https://deb.debian.org/debian/dists/stable/main/installer-amd64/current/images/netboot/netboot.tar.gz",
    }
}
```

The variant is set to `debian11` because in Debian 12, the `osinfo` variant for Debian 12 is not yet installable via libvirt.

To install another distribution, modify the dictionary located in `/usr/lib/python3/dist-packages/mofos/settings.py`.

When the above command is run, Mofos downloads the netboot files and caches the `tar.gz` archive in `$HOME/.cache/template-installer`. Currently, if the netboot archive already exists, Mofos will not download it again. This can cause errors if the cached archive is outdated. If such errors occur during installation, removing the cached archive will force Mofos to download an updated version, which should resolve the issue.

Next, the archive is extracted into `/tmp`, and libvirt is configured to serve its contents via TFTP.

The template virtual machine is then created and set to boot via PXE, installing the specified distribution using the provided preseed file (by default `/usr/share/mofos/templates/debian/preseed.cfg.j2`). This file is a `jinja2` template; before copying it to the TFTP root directory, variables from the configuration files (`ntp`, `proxy`, `dns`, `root_password`) are injected.

At the end of the installation, the `postinstall` script is placed in the TFTP directory and executed on the template. By default, the script located at `/usr/share/mofos/templates/postinstall.sh.j2` is used. This `jinja2` template injects the public SSH key to be configured on the template.

In addition of configuring the root SSH public key, the following operation are performed:
- Disable the standard SSH service and enable a SSHD over virtual sockets (vsock).
- Empty the `/etc/resolv.conf` file.
- Configure the GRUB timeout to 0 second.
- Install an initramfs hook that mounts the overlayfs when partition labeled `overlay` is detected.

Once the installation is complete, the libvirt virtual machine is retrieved and compressed into a local `qcow2` file saved in the current directory.

```
$ mofos template create debian-template
[*] Installing debian-template
[*] Configure the SSH host key of the template
[*] Waiting for the installation to be complete
[*] Installation is complete
[*] Downloading the resulting qcow2 disk
[*] Compressing the disk
[*] Save template's public ssh host key
[+] Template installation finished
[+] Template disk is debian-template-disk.qcow2
```

In addition to the `qcow2` file, this process also creates an entry in the file `$HOME/.local/share/mofos/ssh.json` containing the machine’s name and its public SSH key:

```json
{
  "disk": {
    "debian-template-disk.qcow2": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrbOdOPENEj2KeHrYLdorQe9Ez1b9Bu5agZmgNDMayy"
  }
}
```

This file is automatically used during the import process.

### Import

The next step is to import the created template `qcow2` file into Mofos.

```
$ mofos template import debian-template debian-template-disk.qcow2 http://debian.org/debian/11 
[*] Uploading debian-template-disk.qcow2 to mofos pool
[*] Creating the virtual machine debian-template
[*] Configuring the template metadata
[*] Configuring the SSH key
[+] debian-template successfully imported
```

For now, the `osinfo` variant is mandatory. They can be found in the file:
`/usr/lib/python3/dist-packages/mofos/settings.py`.

Once imported, the template can be seen in the `mofos ls` command:

```
$ mofos ls
+----+-----------------+---------+-------------+-------+-----+--------------+
| Id | Name            | State   | Description | Alias | Cid | IPv4 address |
+----+-----------------+---------+-------------+-------+-----+--------------+
|    | debian-template | shutoff |             |       |     |              |
+----+-----------------+---------+-------------+-------+-----+--------------+
```

From this point, the template can be started and accessed for modification as needed.

```
$ mofos start debian-template
$ mofos ls
+----+-----------------+---------+-------------+-------+-----+----------------+
| Id | Name            | State   | Description | Alias | Cid | IPv4 address   |
+----+-----------------+---------+-------------+-------+-----+----------------+
| 3  | debian-template | running |             |       | 3   | 192.168.90.202 |
+----+-----------------+---------+-------------+-------+-----+----------------+
```

```
$ mofos ssh debian-template --user root
root@linux:~#
```

## Create the upper layer empty disk

The following command creates an empty upper layer with the specified label on the disk’s single partition:

```
$ mofos template create-overlay-disk
```

By default, this disk is set to 50 GB but initially occupies only around 100 MB. This size can be customized in the configuration file.

## Create a virtual machine

Note: It is recommended to always shut down a template before manipulating Mofos virtual machines. Although running a template and its virtual machines simultaneously is supported, it may lead to instability.

```
$ mofos new test
[*] New virtual machine name is test
[+] Virtual machine test successfully created
[*] Triggering post install actions
[*] Create SSH known_hosts entries for test
[*] Waiting for test to be up
[+] test is ready
$ mofos ssh test -u root
Last login: Mon Jun  2 11:09:51 2025 from UNKNOWN
root@linux:~# 
```

Keep in mind that SSH connections are made through virtual sockets, so you cannot directly SSH into the newly created machine. Instead, you must use the mofos ssh command. Alternatively, you can create an SSH configuration specifying a `ProxyCommand `to access the machine’s SSH port:

```
$ mofos inventory --format ssh
Host debian-template
	User user
	PasswordAuthentication no
	IdentityFile /home/user/.ssh/id_ed25519
	ProxyCommand /usr/bin/mofos proxy-cmd %h
	CanonicalizeHostname=no

Host test
	User user
	PasswordAuthentication no
	IdentityFile /home/user/.ssh/id_ed25519
	ProxyCommand /usr/bin/mofos proxy-cmd %h
	CanonicalizeHostname=no
```

```
$ mofos inventory --format ssh > ~/.ssh/mofos
$ echo "Include ~/.ssh/mofos" >> ~/.ssh/config
$ ssh root@test
Linux linux 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jun  2 11:09:51 2025 from UNKNOWN
root@linux:~# 
```

During a `mofos ssh` session, a `ControlMaster` socket is established beforehand to speed up subsequent connections. This is why the MOTD is not displayed.

## Customization

To simplify the customization of templates and virtual machines, Mofos introduces the concept of hooks and tags. For each tag, a corresponding hook (a Bash script) can be executed to perform automated actions on the target virtual machine or template and configure it accordingly.

Minimal hooks are located in `/usr/share/mofos/hooks`. These are simple Bash scripts that receive the following inputs:

```
TAG=$1
NAME=$2
OS=$3
DISTRIB=$4
HOSTNAME=$5
```

### Template - hook install

This mechanism can be leveraged with Ansible to execute playbooks during template installation:

```bash
#!/bin/bash

# During template installation, the machine is not yet managed by mofos,
# the inventory would not working.
# A custom inventory is created on the fly using the given tag as main ansible
# group and the distribution as secondary.

TAG=$1
NAME=$2
OS=$3
DISTRIB=$4
HOSTNAME=$5

if [ -z "${TAG}" ] || [ -z "${NAME}" ] || [ -z "${DISTRIB}" ] ; then
  exit 1
fi

# Create inventory
ANSIBLE_DIRECTORY="/home/user/Documents/ansible"
RANDOM_SUFFIX=$(printf "%x" $RANDOM)
INVENTORY_FILE="${ANSIBLE_DIRECTORY}/inventory-${NAME}-${RANDOM_SUFFIX}.ini"

trap 'rm -f "${INVENTORY_FILE}"; exit' EXIT

cat > $INVENTORY_FILE <<EOF
[all:vars]
ansible_ssh_common_args="-o ProxyCommand='mofos proxy-cmd %h' -o CanonicalizeHostname=no"

[${TAG}]
${NAME}

[${DISTRIB}]
${NAME}
EOF

export ANSIBLE_CONFIG="/home/user/Documents/ansible/ansible.cfg"
export ANSIBLE_VERBOSITY=1

/usr/bin/ansible-playbook \
  -i "${INVENTORY_FILE}" \
  -l "${NAME}" \
  /home/user/Documents/ansible/playbooks/pentest/install.yml
```

This script dynamically creates an inventory and runs a playbook against it.

### Virtual machine - hook new

During virtual machine creation, another hook can be used, for example, to randomize the hostname.

By default, Mofos generates an alias based on the classic Windows naming convention (e.g., `DESKTOP-2BF9753`). This name, along with other information, is passed to the hook script:

```
#!/bin/bash

TAG=$1
NAME=$2
OS=$3
DISTRIB=$4
HOSTNAME=$5

if [ -z "${TAG}" ] || [ -z "${NAME}" ] || [ -z "${OS}" ] ; then
  exit 1
fi

if [ -z "${HOSTNAME}" ] ; then
  HOSTNAME="${NAME}"
fi

mofos run -u root "${NAME}" "echo ${HOSTNAME} > /etc/hostname && hostname ${HOSTNAME}"
```

Next, the configuration should be edited to enable this hook:

```
[hooks.test]
new = "/home/user/.config/mofos/hooks/new.sh"
```


Then, during virtual machine creation, this script will be executed:

```
$ mofos new test2 --tags test 
[*] New virtual machine name is test2
[+] Virtual machine test2 successfully created
[*] Triggering post install actions
[*] Create SSH known_hosts entries for test2
[*] Waiting for test2 to be up
[*] Running new hook: test
[+] test2 is ready
```

```
$ mofos ssh test2 -u root
Last login: Mon Jun  2 11:09:51 2025 from UNKNOWN
root@DESKTOP-2BF9753:~# 
```

Similar to the installation phase, Ansible playbooks can also be executed at this stage. In this case, the `mofos inventory` command can be used to generate an Ansible inventory, simplifying the process of selecting and accessing virtual machines:

```
$ mofos inventory 
{
    "_meta": {
        "hostvars": {
            "debian-template": {
                "ansible_host": "debian-template",
                "ansible_ssh_common_args": "-o ProxyCommand='/usr/bin/mofos proxy-cmd %h'  -o CanonicalizeHostname=no"
            },
            "test": {
                "ansible_host": "test",
                "ansible_ssh_common_args": "-o ProxyCommand='/usr/bin/mofos proxy-cmd %h'  -o CanonicalizeHostname=no"
            },
            "test2": {
                "ansible_host": "test2",
                "ansible_ssh_common_args": "-o ProxyCommand='/usr/bin/mofos proxy-cmd %h'  -o CanonicalizeHostname=no"
            }
        }
    },
    "debian": [
        "debian-template",
        "test",
        "test2"
    ],
    "test": [
        "test2"
    ]
```

Note that groups are created based on the distribution variant as well as tags. These groups can be used to load different variables.

For example, the script below runs an arbitrary playbook:

```bash
#!/bin/bash

TAG=$1
NAME=$2
OS=$3
DISTRIB=$4
HOSTNAME=$5

if [ -z "${TAG}" ] || [ -z "${NAME}" ] || [ -z "${OS}" ] ; then
  exit 1
fi

if [ -z "$HOSTNAME" ] ; then
  HOSTNAME=$NAME
fi

if [ $OS == "windows" ] ; then
  TAGS="hostname,desktop"
else
  TAGS="hostname,hosts,desktop"
fi

export ANSIBLE_CONFIG="/home/user/Documents/ansible/ansible.cfg"
export ANSIBLE_VERBOSITY=0

/usr/bin/ansible-playbook \
  -i /home/user/Documents/ansible/inventory.py \
  -l "${NAME}" \
  -t "${TAGS}" \
  -e "hostname=${HOSTNAME}" \
  /home/user/Documents/ansible/playbooks/pentest/update.yml
```

### Virtual machine - hook start

Similarly, the start hook is executed when a virtual machine starts. It is typically used to launch services required by the virtual machine.

For example, to enable seamless Windows integration within the virtual machine, you can install `Xpra`.

First install `ansible`:

```
# apt install ansible
```

Next, run the user playbook located in the `ansible` directory. Before doing so, edit the `playbooks/user.yml` file to update the password hash and the public SSH key to be installed in the user’s home directory.

```
~/mofos/ansible$ ls
ansible.cfg  ansible.log  inventory.sh  playbooks
```

```
$ ansible-playbook playbooks/user.yml -l test2
Using /home/user/mofos/ansible/ansible.cfg as config file
[WARNING]: Found both group and host with same name: test

PLAY [Create and configure a user]

[...]

PLAY RECAP
test2 : ok=4 changed=2 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0   
```

Afterward, you can SSH into this user account, provided the configuration specifies this user as the default:

```
$ mofos ssh test2
user@DESKTOP-2BF9753:~$ 
```

Next, run the `Xpra` playbook. This playbook installs packages from Debian mirrors. Please note that the Mofos network does not configure DNS, proxy, or a default gateway by default. These must be set up before running the playbook.

No modifications to the playbook are required by default.

```
ansible-playbook playbooks/xpra.yml -l test2
```

This playbook installs and configures Xpra and starts the `xpra` service on the virtual machine.

The remote service can be started manually using:

```
user@DESKTOP-2BF9753:~$ systemctl --user start xpra
```

Otherwise, the service will start automatically at the next reboot.

Then, the local client service can also be start manuallly:

```
$ mofos xpra test2
```

Back on the virtual machine, the display should be set to `:10` (the default), after which a graphical application can be launched and will appear within the host’s desktop environment.

```
user@DESKTOP-2BF9753:~$ export DISPLAY=:10
user@DESKTOP-2BF9753:~$ xterm
```

To ensure this mechanism runs smoothly and automatically, the `mofos xpra` command can be start from the start hook.

```bash
#!/bin/bash

TAG=$1
NAME=$2
OS=$3
DISTRIB=$4
HOSTNAME=$5

if [ -z "${TAG}" ] || [ -z "${NAME}" ] ; then
exit 1
fi

mofos xpra "${NAME}"
```

## Features

### Setup notification when starting or stopping VM

To be inform of the start and stop of `libvirt/qemu` machines, the `libvirt` `qemu` hook nay be modified to specify the name of the host user (by default `user`):

```
# sed 's/USER = "user"/USER = "foobar"/' /etc/libvirt/hooks/qemu.d/90-mofos
```

Then, enable and start the `mofos-libvirt-notifier` socket:

```
systemctl --user enable --now mofos-libvirt-notifier.socket
```

### Clipboard

Mofos can also manage the clipboard between virtual machines and the host. The idea is to configure a specific keybind to trigger an SSH connection to the currently focused VM, either to pull the X11 clipboard or to push content to it.

To push content in the virtual machine X11 clipboard:

```
mofos clipboard in pentest-0
```

To pull content from the virtual machine X11 clipboard:

```
mofos clipboard out pentest-0
```

For each operation, mofos will establish an SSH connection to the virtual machine and use xclip and on the host `wl-copy` or `xclip` according to the windows technology (wayland vs X11).

The machine name in the trace above may be omitted, in this case, the script will identify the currently focused virtual machine and target it.

### Setup routing between machines

Two options exist in mofos to route a VM:
- `mofos route` that takes a gateway and configure an `ip rule` on the host to route the virtual machine through this gateway.
- `mofos pivot` that takes another mofos machine, retrieve its IP address and
configure it as default gateway for the current virtual machine.

Both options may take a DNS server to configure it.

### Setup tunneling through pentest boxes

The `mofos tunnel` command sets up a SSH vpn (`ssh -w`) to route the traffic of a
mofos machine through a server. This feature relies on few configurations:

Concretely the `mofos tunnel` command does the following actions (no black magic here):
1. Create a local tun interface (`sudo /usr/libexec/mofos/mofosnet.py tun add pentest_box`) and assign an IP address to this interface. 
2. Create a tun on a remote server and link it wit the local tun created previously (`/usr/libexec/mofos/mofosnet.py sshvpn start pentest_box`).
3. Route the traffic of a mofos machine through the gateway of the remote box (`/usr/libexec/mofos/mofosnet.py route mofos_vm_ip gateway_ip`), the default gateway of the mofos virtual machine is also changed.

As for `route` and `pivot` commands, a DNS may be provided to configure it as
well.

### USB management

The `mofos usb` commmand allows managing usb devices.

Devices are identified by their ID (vendor_id:product_id) which is needed for the attach and detach command:

```console
$ mofos ls usb
+-----------+------------------------------------------------+-------------+
| ID        | Device                                         | Attached to |
+-----------+------------------------------------------------+-------------+
| 0bda:8153 | Realtek, RTL8153 Gigabit Ethernet Adapter      |             |
| 046d:c077 | Logitech, Mouse                                |             |
| 0a5c:5842 | Broadcom Corp, 58200                           |             |
| 1bcf:28d2 | CN0Y9V728LG003AGBCJZA01, Integrated_Webcam_FHD |             |
+-----------+------------------------------------------------+-------------+
$ mofos usb attach pentest-1 0bda:8153
$ mofos usb
+-----------+------------------------------------------------+-------------+
| ID        | Device                                         | Attached to |
+-----------+------------------------------------------------+-------------+
| 0bda:8153 | Realtek, RTL8153 Gigabit Ethernet Adapter      | pentest-1   |
| 046d:c077 | Logitech, Mouse                                |             |
| 0a5c:5842 | Broadcom Corp, 58200                           |             |
| 1bcf:28d2 | CN0Y9V728LG003AGBCJZA01, Integrated_Webcam_FHD |             |
+-----------+------------------------------------------------+-------------+
$ mofos usb detach pentest-4 0bda:8153
```

The `force` option detach and re-attach a device. It is commonly used to
re-attach a device that has been unplugged without being first detached.

Note: attaching a USB device is only valid for the current life of the virtual machine. When it stops, the device is automatically detached.

### PCI devices management

Similar to USB devices, mofos allows attaching a PCI device to a running virtual machine, the commands are the same. 

An additional limitations concerns some PCI devices that belongs to a group. For example, attaching the ethernet board to a running virtual machine may need to move the entire PCI group inside the virtual machine. As it cannot be done sequentially, it is not supported yet. However, for a unique PCI device such as a Wi-Fi network card, it works fine.

### Shared folders

The `mofos mount` command creates a share folders and can mount the newly added filesystem to a directory inside the virtual machine. The `mofos umount` will unmount the directory and remove the share folders from the virtual machine configuration.

This mechanism relies on the `virtiofsd` technology that requires enabling shared memory, this is now done by default when creating a virtual machine. Otherwise, the following command will enable it:

```console
virt-xml -c qemu:///system --edit --memorybacking source.type=memfd,access.mode=shared DOMAIN
```

Furthermore, the provided AppArmor policies restrict the directories that can be shared by the host. This is done to prevent your user to configure a share on the `/etc` directory or the filesystem root and modify using root privileges within the virtual machine. Therefore, it is needed to modify the `usr.lib.qemu.virtiofsd` policy to allow sharing arbitrary directories.

Two lines should be adapted:

```
@{SHARE_DIRS}=/data/libvirt/shares/*/ /home/user/Public/**/
[...]
pivot_root /data/libvirt/shares/*/,
pivot_root /home/user/Public/**/,
```

The `SHARE_DIRS` variable is reused in the policy, however, due to apparmor limitations, it is not possible to reuse it for `pivot_root` directives. Therefore, it is required to manually adapt the `pivot_root` directives for each shared directories.

To mount a local directory:

```
mofos mount test ./Public/share -d /home/user/share
```

In order to not disrupt the virtual machine where the share is to be mounted, if the remote directory is not empty a warning is issued and the script let you manually perform the mount operation.

Finally, the mount operation is not persistent and should be re-issued at each reboot.

## Windows machines

To create Windows virtual machines, a template machine must be created manually first. The disk of this template is then used as a backing file to create child machines. By default, Windows virtual machines created with Mofos are not pre-configured. However, it is possible to configure Mofos to perform post-configuration tasks, such as changing the hostname and adding a dedicated entry in the `known_hosts` file, by using hooks.

To enable the post creation setup, the following prerequisites are mandatory:
- OpenSSH server should be listening
- An SSH key should be configured to smoothly authenticate as an Administrators user. The `authorized_keys` has to be created in `C:\Program Data\ssh\administrators_authorized_keys` and specific ACL.

```powershell
$admin_group = "Administrators"
$system = "SYSTEM"

$acl = Get-Acl C:\ProgramData\ssh\administrators_authorized_keys
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule($admin_group,"FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule($system,"FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl
```
- OpenSSH should be configured with a `PowerShell` shell instead of `cmd.exe`.

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
                 -Name DefaultShell `
                 -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
                 -PropertyType String `
                 -Force
```

## Autocompletion

Autocompletion should be handled out-of-the-box for `bash` and `fish`. For `zsh`, it may be required to run the following commands:

```
autoload -Uz compinit
compinit
source /usr/share/zsh/vendor-completions/_mofos
```

## IP addresses overlap

Virtual machines based on the same template disk may obtain the same IP address even though the mac address of their network card changes due to DHCP identifier. This behavior can be changed by editing the template's network configuration:

With systemd-networkd:

```
[Match]
Name=eth0

[Network]
DHCP=yes
MulticastDNS=no
IPv6AcceptRA=no

[DHCP]
ClientIdentifier=mac
```

With legacy network interfaces `/etc/network/interfaces`:

```
iface eth0 inet dhcp
  client no
```
