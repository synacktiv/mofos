# ============================================================================ #
# envvars
# ============================================================================ #
PROJNAME=mofos
PYTHON=python3
PYTHON_SITE_PACKAGES := $(shell python3 -c 'import site; print("\n".join(site.getsitepackages()))' | grep "/usr/local/lib/")
PREFIX ?= "/usr/local"
IS_ROOT := $(shell id -u)
DEFAULT_POOL := "mofos"
INSTALL_POOL := "mofos_install"
NET_NAME := "mofos"
NET_IFACE := "mof0"
NET_ADDRESS := "192.168.90.0/24"

# ============================================================================ #
# versioning
# ============================================================================ #
VERSION_BASE      = $(shell cat VERSION)
DEFAULT_REVISION ?= "head"
PROJECT_REVISION ?= $(shell git rev-parse --short HEAD || echo $(DEFAULT_REVISION))
PROJECT_VERSION  ?= $(VERSION_BASE).$(PROJECT_REVISION)
version:
	@echo $(PROJECT_VERSION)
DEBIAN_VER = $(shell lsb_release -c -s 2>/dev/null)

# ============================================================================ #
# deb packages
# ============================================================================ #
deb: 
	sed -i '1 s/^\([^)]*\) ([^)]*)/\1 ($(PROJECT_VERSION)~$(DEBIAN_VER))/' debian/changelog
	dpkg-buildpackage -i -b -uc -us
	mv ../$(PROJNAME)_*.deb ./
	# remove buildinfo & changes
	-@rm -f ../$(PROJNAME)_*.buildinfo ../$(PROJNAME)_*.changes ../$(PROJNAME)_*.build
	dh_clean
	# rollback version change, to avoid having a modified file in git
	sed -i '1 s/^\([^)]*\) ([^)]*)/\1 (1.0.0-head)/' debian/changelog

# ============================================================================ #
# cleanup
# ============================================================================ #
clean:
	-@rm -rf $(shell find . -name __pycache__ -type d)
	-@rm -rf $(shell find . -name '*.pyc' -type f )
	-@rm -f .coverage build .hypothesis
	-@rm -f *.deb *.buildinfo *.changes
	-@rm -rf *.egg-info py/*.egg-info .pybuild .pytest_cache
	-@rm -rf debian/$(PYTHON)-$(PROJNAME) debian/debhelper-build-stamp debian/*.log
	-@rm -rf debian/.debhelper debian/*.debhelper debian/files debian/*.substvars
	-@dh_clean

check_root:
ifeq ($(IS_ROOT), 0)
	@echo "Running as root. Proceeding with installation."
else
	@echo "Error: This target requires root privileges."
	@echo "Please run 'sudo $(MAKE) local_install' or 'su -c \"$(MAKE) local_install\"'."
	@exit 1
endif

# ============================================================================ #
# install
# ============================================================================ #
local_install: check_root
	install -o root -g root -d -m 0755 $(PYTHON_SITE_PACKAGES)
	cp -r mofos $(PYTHON_SITE_PACKAGES)/
	install -o root -g root -m0755 bin/mofos /usr/bin/
	install -o root -g root -m 0644 -D utils/mofosnet/mofosnet.toml /etc/mofos/
	install -o root -g root -m 0644 -D config.sample.toml config.minimal.toml $(PREFIX)/share/mofos/
	install -o root -g root -m 0755 -D utils/mofosnet/mofosnet.py $(PREFIX)/libexec/mofos/
	install -o root -g root -m 0644 -D utils/mofosnet/mofosnet.toml /etc/mofos/
	install -o root -g root -m 0755 -D utils/qemu.d/90-mofos /etc/libvirt/hooks/qemu.d/
	install -o root -g root -m 0644 -D utils/sudoers.d/mofos /etc/sudoers.d/
	install -o root -g root -m 0644 -D utils/pool/install.xml $(PREFIX)/share/mofos/pool/
	install -o root -g root -m 0644 -D utils/pool/mofos.xml $(PREFIX)/share/mofos/pool/
	install -o root -g root -m 0644 -D utils/bridge/mof0.xml $(PREFIX)/share/mofos/bridge/
	install -o root -g root -m 0644 -D utils/systemd/mofos-libvirt-notifier.socket $(PREFIX)/lib/systemd/user/
	install -o root -g root -m 0644 -D utils/systemd/mofos-libvirt-notifier@.service $(PREFIX)/lib/systemd/user/
	install -o root -g root -m 0644 -D utils/systemd/ssh-agent-proxy.service $(PREFIX)/lib/systemd/user/
	install -o root -g root -m 0644 -D utils/systemd/sudo-auth-proxy.service $(PREFIX)/lib/systemd/user/
	install -o root -g root -m 0644 -D utils/polkit/mofos.rules /etc/polkit-1/rules.d/
	install -o root -g root -m 0644 -D templates/postinstall.sh.j2 $(PREFIX)/share/mofos/templates/
	install -o root -g root -m 0644 -D templates/preseed.cfg.j2 $(PREFIX)/share/mofos/templates/debian
	install -o root -g root -m 0755 -D hooks/install.sh hooks/new.sh hooks/poststart.sh $(PREFIX)/share/mofos/hooks/
	install -o root -g root -m 0644 -D utils/shell/autocompletions/bash/mofos /etc/bash_completion.d/
	install -o root -g root -m 0644 -D utils/shell/autocompletions/fish/mofos.fish $(PREFIX)/share/fish/vendor_completions.d/
	install -o root -g root -m 0644 -D utils/shell/autocompletions/zsh/_mofos $(PREFIX)/share/zsh/vendor-completions/
	install -o root -g root -m 0644 -D utils/sudo-auth-proxy.py utils/ssh-agent-proxy.py $(PREFIX)/share/mofos/utils/

	sed -i "s|/usr/libexec/mofos/mofosnet.py|$(PREFIX)/libexec/mofos/mofosnet.py|" /etc/sudoers.d/mofos
	sed -i "s|/usr/libexec/mofos/mofosnet.py|$(PREFIX)/libexec/mofos/mofosnet.py|" $(PYTHON_SITE_PACKAGES)/mofos/settings.py
	sed -i "s|/usr/share/mofos/config.minimal.toml|$(PREFIX)/share/mofos/config.minimal.toml|" $(PYTHON_SITE_PACKAGES)/mofos/settings.py

install_apparmor: check_root
	install -o root -g root -D utils/apparmor.d/usr.sbin.libvirtd utils/apparmor.d/usr.lib.qemu.virtiofsd $(PREFIX)/share/mofos/apparmor/
	install -o root -g root -D utils/apparmor.d/usr.lib.qemu.virtiofsd utils/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/
	systemctl reload apparmor

configure: check_root
	bash debian/postinst make $(PREFIX) $(DEFAULT_POOL) $(INSTALL_POOL) $(NET_NAME) $(NET_IFACE) $(NET_ADDRESS)
