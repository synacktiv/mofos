# Apt

Configure the apt package manager.
* Add CA certificates to /etc/apt
* Add configuration files to /etc/apt/apt.conf.d
* Add keys to /etc/apt/trusted.gpg.d
* Add sources to /etc/apt/sources.list.d
* Add preferences to /etc/preferences.d

```
apt:
  certificates:
    - src: apt/custom.pem
      dest: /etc/apt/custom.pem
  confs:
    - name: custom
      src: apt/apt.conf.d/99custom
      priority: 99
  keys_:
    - name: custom.gpg
      src: apt/keys/custom.gpg
  sources:
    - name: debian
      entries:
        - type: deb
          uri: http://ftp.fr.debian.org/debian/
          suite: stable
          components:
            - main
            - contrib
            - non-free
        - type: deb-src
          uri: http://ftp.fr.debian.org/debian/
          suite: stable
          components:
            - main
            - contrib
            - non-free
    - name: custom
      entries:
        - type: deb
          options:
            - signed-by=/etc/apt/keyring/custom.gpg
          suite: stable
          components:
            - main
  preferences:
    purge: yes
    includes:
      - name: xpra
        entries:
          - packages: xpra 
            version: "5*"
            origin: xpra.org
            priority: 999
          - packages: "*"
            origin: xpra.org
            priority: 1
```
