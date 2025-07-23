# ============================================================================ #
# envvars
# ============================================================================ #
PROJNAME=mofos
PYTHON=python3
PYTHON_SITE_PACKAGES ?= $(shell python3 -c 'import site; print("\n".join(site.getsitepackages()))' | grep "/usr/local/lib/")
PREFIX ?= "/usr/local"
ETC_PATH ?= "/etc"
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
	install -o root -g root -m 0755 -D -t $(PREFIX)/bin/ bin/mofos
	install -o root -g root -m 0644 -D -t $(ETC_PATH)/mofos/ utils/mofosnet/mofosnet.toml
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/mofos/ config.sample.toml config.minimal.toml
	install -o root -g root -m 0755 -D -t $(PREFIX)/libexec/mofos/ utils/mofosnet/mofosnet.py
	install -o root -g root -m 0644 -D -t $(ETC_PATH)/mofos/ utils/mofosnet/mofosnet.toml
	install -o root -g root -m 0755 -D -t $(ETC_PATH)/libvirt/hooks/qemu.d/ utils/qemu.d/90-mofos
	install -o root -g root -m 0644 -D -t $(ETC_PATH)/sudoers.d/ utils/sudoers.d/mofos
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/mofos/pool/ utils/pool/install.xml
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/mofos/pool/ utils/pool/mofos.xml
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/mofos/bridge/ utils/bridge/mof0.xml
	install -o root -g root -m 0644 -D -t $(PREFIX)/lib/systemd/user/ utils/systemd/mofos-libvirt-notifier.socket
	install -o root -g root -m 0644 -D -t $(PREFIX)/lib/systemd/user/ utils/systemd/mofos-libvirt-notifier@.service
	install -o root -g root -m 0644 -D -t $(PREFIX)/lib/systemd/user/ utils/systemd/ssh-agent-proxy.service
	install -o root -g root -m 0644 -D -t $(PREFIX)/lib/systemd/user/ utils/systemd/sudo-auth-proxy.service
	install -o root -g root -m 0644 -D -t $(ETC_PATH)/polkit-1/rules.d/ utils/polkit/mofos.rules
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/mofos/templates/ templates/postinstall.sh.j2
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/mofos/templates/debian/ templates/preseed.cfg.j2
	install -o root -g root -m 0755 -D -t $(PREFIX)/share/mofos/hooks/ hooks/install.sh hooks/new.sh hooks/poststart.sh
	install -o root -g root -m 0644 -D -t $(ETC_PATH)/bash_completion.d/ utils/shell/autocompletions/bash/mofos
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/fish/vendor_completions.d/ utils/shell/autocompletions/fish/mofos.fish
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/zsh/vendor-completions/ utils/shell/autocompletions/zsh/_mofos
	install -o root -g root -m 0644 -D -t $(PREFIX)/share/mofos/utils/ utils/sudo-auth-proxy.py utils/ssh-agent-proxy.py

	sed -i "s|/usr/libexec/mofos/mofosnet.py|$(PREFIX)/libexec/mofos/mofosnet.py|" $(ETC_PATH)/sudoers.d/mofos
	sed -i "s|/usr/libexec/mofos/mofosnet.py|$(PREFIX)/libexec/mofos/mofosnet.py|" $(PYTHON_SITE_PACKAGES)/mofos/settings.py
	sed -i "s|/usr/share/mofos/config.minimal.toml|$(PREFIX)/share/mofos/config.minimal.toml|" $(PYTHON_SITE_PACKAGES)/mofos/settings.py

install_apparmor: check_root
	install -o root -g root -D -t $(PREFIX)/share/mofos/apparmor/ utils/apparmor.d/usr.sbin.libvirtd utils/apparmor.d/usr.lib.qemu.virtiofsd
	install -o root -g root -D -t $(ETC_PATH)/apparmor.d/ utils/apparmor.d/usr.lib.qemu.virtiofsd utils/apparmor.d/usr.sbin.libvirtd
	systemctl reload apparmor

configure: check_root
	bash debian/postinst make $(PREFIX) $(DEFAULT_POOL) $(INSTALL_POOL) $(NET_NAME) $(NET_IFACE) $(NET_ADDRESS)
