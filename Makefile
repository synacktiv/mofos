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
VERSION_BASE      = 1.0.0
PROJECT_REVISION ?= $(shell git rev-parse --short HEAD || echo @@revision@@)
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
	mkdir -p $(PYTHON_SITE_PACKAGES)
	mkdir -p $(PREFIX)/share/mofos
	mkdir -p $(PREFIX)/share/mofos/templates
	mkdir -p $(PREFIX)/share/mofos/hooks
	mkdir -p $(PREFIX)/share/mofos/utils
	mkdir -p $(PREFIX)/share/mofos/apparmor
	mkdir -p $(PREFIX)/share/mofos/pool
	mkdir -p $(PREFIX)/share/mofos/bridge
	mkdir -p /etc/mofos
	mkdir -p /etc/libvirt/hooks/qemu.d
	mkdir -p /etc/bash_completion.d/ 
	mkdir -p $(PREFIX)/share/fish/vendor_completions.d/ 
	mkdir -p $(PREFIX)/share/zsh/vendor-completions/
	mkdir -p $(PREFIX)/libexec/mofos
	mkdir -p $(PREFIX)/lib/systemd/user
	install -o root -g root -m0755 bin/mofos /usr/bin/
	cp -r mofos $(PYTHON_SITE_PACKAGES)/
	cp utils/mofosnet/mofosnet.toml /etc/mofos/
	cp config.sample.toml $(PREFIX)/share/mofos/
	cp config.minimal.toml $(PREFIX)/share/mofos/
	install -o root -g root -m0755 utils/mofosnet/mofosnet.py $(PREFIX)/libexec/mofos/
	cp utils/mofosnet/mofosnet.toml /etc/mofos/
	install -o root -g root -m0755 utils/qemu.d/90-mofos /etc/libvirt/hooks/qemu.d/
	cp utils/sudoers.d/mofos /etc/sudoers.d/
	cp utils/pool/install.xml $(PREFIX)/share/mofos/pool/
	cp utils/pool/mofos.xml $(PREFIX)/share/mofos/pool/
	cp utils/bridge/mof0.xml $(PREFIX)/share/mofos/bridge/
	cp utils/systemd/mofos-libvirt-notifier.socket $(PREFIX)/lib/systemd/user/
	cp utils/systemd/mofos-libvirt-notifier@.service $(PREFIX)/lib/systemd/user/
	cp utils/systemd/ssh-agent-proxy.service $(PREFIX)/lib/systemd/user/
	cp utils/systemd/sudo-auth-proxy.service $(PREFIX)/lib/systemd/user/
	cp utils/polkit/mofos.rules /etc/polkit-1/rules.d/
	cp templates/postinstall.sh.j2 $(PREFIX)/share/mofos/templates/
	cp templates/preseed.cfg.j2 $(PREFIX)/share/mofos/templates/debian
	cp hooks/install.sh $(PREFIX)/share/mofos/hooks/
	cp hooks/new.sh $(PREFIX)/share/mofos/hooks/
	cp hooks/poststart.sh $(PREFIX)/share/mofos/hooks/
	cp utils/shell/autocompletions/bash/mofos /etc/bash_completion.d/
	cp utils/shell/autocompletions/fish/mofos.fish $(PREFIX)/share/fish/vendor_completions.d/
	cp utils/shell/autocompletions/zsh/_mofos $(PREFIX)/share/zsh/vendor-completions/
	cp utils/sudo-auth-proxy.py $(PREFIX)/share/mofos/utils/
	cp utils/ssh-agent-proxy.py $(PREFIX)/share/mofos/utils/

	sed -i "s|/usr/libexec/mofos/mofosnet.py|$(PREFIX)/libexec/mofos/mofosnet.py|" /etc/sudoers.d/mofos
	sed -i "s|/usr/libexec/mofos/mofosnet.py|$(PREFIX)/libexec/mofos/mofosnet.py|" $(PYTHON_SITE_PACKAGES)/mofos/settings.py
	sed -i "s|/usr/share/mofos/config.minimal.toml|$(PREFIX)/share/mofos/config.minimal.toml|" $(PYTHON_SITE_PACKAGES)/mofos/settings.py

	chmod -R u=rwX,g=rX,o=rX $(PYTHON_SITE_PACKAGES)
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/mofos
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/mofos/templates
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/mofos/hooks
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/mofos/utils
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/mofos/apparmor
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/mofos/pool
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/mofos/bridge
	chmod -R u=rwX,g=rX,o=rX /etc/mofos
	chmod -R u=rwX,g=rX,o=rX /etc/libvirt/hooks/qemu.d
	chmod -R u=rwX,g=rX,o=rX /etc/bash_completion.d/ 
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/fish/vendor_completions.d/ 
	chmod -R u=rwX,g=rX,o=rX /usr/local/share/zsh/vendor-completions/
	chmod -R u=rwX,g=rX,o=rX /usr/local/libexec/mofos
	chmod -R u=rwX,g=rX,o=rX /usr/local/lib/systemd/user

install_apparmor: check_root
	cp utils/apparmor.d/usr.sbin.libvirtd $(PREFIX)/share/mofos/apparmor/
	cp utils/apparmor.d/usr.lib.qemu.virtiofsd $(PREFIX)/share/mofos/apparmor/
	cp utils/apparmor.d/usr.lib.qemu.virtiofsd /etc/apparmor.d/
	cp utils/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/
	systemctl reload apparmor

configure: check_root
	bash debian/postinst make $(PREFIX) $(DEFAULT_POOL) $(INSTALL_POOL) $(NET_NAME) $(NET_IFACE) $(NET_ADDRESS)
