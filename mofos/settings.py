from tomllib import load as toml_load
from os import environ
from os.path import join
from dataclasses import dataclass
from typing import Dict, Any, Optional

import logging

from mofos.lib.logger import VmLogger

log: VmLogger = logging.getLogger(__name__)  # type: ignore

PROJECT = "mofos"
HOME = environ["HOME"]
NET_HELPER = "/usr/libexec/mofos/mofosnet.py"

# Leave this be, it is used to build the ansible inventory.
LIBVIRT_OS_VARIANTS = {
    "http://microsoft.com/win/11": "win11",
    "http://microsoft.com/win/2k22": "win2k22",
    "http://microsoft.com/win/10": "win10",
    "http://archlinux.org/archlinux/rolling": "arch",
    "http://debian.org/debian/11": "debian",
    "http://debian.org/debian/12": "debian",
    "http://libosinfo.org/linux/2022": "linux22",
}


class Config:
    cnf: Dict[Any, Any]

    def get(self, path: str, default_value: Any = None) -> Any:
        elements = path.split(".")
        # browse the dictionaries
        leave: Dict[Any, Any] = self.cnf
        dicts = elements[:-1]
        last = elements[-1]
        for dic in dicts:
            leave = leave.get(dic, {})

        return leave.get(last, default_value)

    def __init__(self) -> None:
        try:
            with open(join(HOME, ".config", "mofos", "config.toml"), "rb") as fp:
                self.cnf = toml_load(fp)
        except FileNotFoundError:
            log.error(
                "Copy the sample configuration file from /usr/share/mofos/config.minimal.toml to ~/.config/mofos/config.toml"
            )
            raise SystemExit(1)

        # Defaults
        self.defaults = Defaults(
            self.get("defaults.ram", 8192),
            self.get("defaults.cpus", 4),
            self.get("defaults.tags", []),
            self.get("defaults.vsock", True),
            self.get("defaults.shmem", True),
            Template(name=self.get("defaults.template.name", "")),
            Overlay(disk=self.get("defaults.overlay.disk", "overlay.qcow2")),
        )

        # Runtime
        self.runtime = Runtime(
            Vsock(
                self.get("runtime.vsock.ssh_port", 65022),
                self.get("runtime.vsock.ssh_agent_proxy_port", 65000),
                self.get("runtime.vsock.sudo_auth_port", 65002),
                self.get("runtime.vsock.socat_bin_path", "/usr/bin/socat"),
            )
        )

        # SSH
        self.ssh = Ssh(
            self.get("ssh.port", 22),
            self.get("ssh.user", None),
            self.get("ssh.key", None),
            self.get("ssh.cmd", "/usr/bin/ssh"),
            self.get(
                "ssh.options",
                (
                    "-o PasswordAuthentication=no "
                    "-o KbdInteractiveAuthentication=no "
                    "-o CanonicalizeHostname=no"
                ),
            ),
            self.get("ssh.known_hosts_file", f"{HOME}/.ssh/known_hosts"),
            Agent(
                self.get("ssh.agent.path", None),
                self.get("ssh.agent.systemd_unit", None),
            ),
            Controlmaster(self.get("ssh.controlmaster.path", None)),
        )
        self.ssh.key = join(HOME, self.ssh.key[1:])
        self.ssh.controlmaster.path = join(HOME, self.ssh.controlmaster.path[1:])
        self.ssh.options = (
            f"{self.ssh.options} "
            f"-o ControlPath={self.ssh.controlmaster.path}/%r@%h:%p"
        )
        self.ssh.cmd = f"{self.ssh.cmd} {self.ssh.options}"

        # Libvirt
        self.libvirt = Libvirt(
            self.get("libvirt.dnsmasq_home", "/var/lib/libvirt/dnsmasq"),
            self.get("libvirt.qemu", "qemu:///system"),
            self.get("libvirt.disks", "/var/lib/libvirt/images"),
            self.get("libvirt.pool", PROJECT),
            self.get("libvirt.network", PROJECT),
            self.get("libvirt.interface", "mof0"),
        )
        self.libvirt.disks = join(self.libvirt.disks, self.libvirt.pool)

        # Install
        self.install = Install(
            self.get("install.preseed"),
            self.get("install.pool", "mofos_install"),
            self.get("install.size", 50),
            # Variables
            Variables(
                self.get("install.variables.ntp", ""),
                self.get("install.variables.dns", ""),
                self.get("install.variables.proxy", ""),
                self.get("install.variables.root_password", ""),
            ),
            # Late_command
            Late_command(
                self.get("install.late_command.script", ""),
                Late_command_variables(
                    root_ssh_pubkey=self.get(
                        "install.late_command.variables.root_ssh_pubkey", ""
                    )
                ),
            ),
        )
        self.xpra = Xpra(
            self.get("xpra.display", ":10"),
            self.get("xpra.cmd", "/usr/bin/xpra attach"),
            self.get(
                "xpra.options", "--dpi 96 --notification=off --clipboard=no --tray=no"
            ),
        )
        self.tools = Tools(self.get("tools.dmenu", "/usr/bin/dmenu"))
        self.pivot = Pivot(
            Box(self.get("pivot.box.file", None), self.get("pivot.box.suffix", None))
        )
        self.hooks = Hooks.load(self.get("hooks"))


@dataclass
class Defaults:
    ram: int
    cpus: int
    tags: list[str]
    vsock: bool
    shmem: bool
    template: "Template"
    overlay: "Overlay"


@dataclass
class Template:
    name: Optional[str]


@dataclass
class Overlay:
    disk: str


@dataclass
class Runtime:
    vsock: "Vsock"


@dataclass
class Vsock:
    ssh_port: int
    ssh_agent_proxy_port: int
    sudo_auth_port: int
    socat_bin_path: str


@dataclass
class Ssh:
    port: int
    user: str
    key: str
    cmd: str
    options: str
    known_hosts_file: str
    agent: "Agent"
    controlmaster: "Controlmaster"


@dataclass
class Agent:
    path: str
    systemd_unit: str


@dataclass
class Controlmaster:
    path: str


@dataclass
class Libvirt:
    dnsmasq_home: str
    qemu: str
    disks: str
    pool: str
    network: str
    interface: str


@dataclass
class Install:
    preseed: str
    pool: str
    size: int
    variables: "Variables"
    late_command: "Late_command"


@dataclass
class Variables:
    ntp: str
    dns: str
    proxy: str
    root_password: str


@dataclass
class Late_command:
    script: str
    variables: "Late_command_variables"


@dataclass
class Late_command_variables:
    root_ssh_pubkey: str


@dataclass
class Hooks:
    new: Optional[str]
    start: Optional[str]
    install: Optional[str]

    @classmethod
    def load(cls, conf: Dict[str, Any]) -> Dict[str, "Hooks"]:
        objects = {}
        for k, v in conf.items():
            if k not in cls.__dataclass_fields__:
                objects[k] = Hooks(
                    v.get("new", conf.get("new", None)),
                    v.get("start", conf.get("start", None)),
                    v.get("install", conf.get("install", None)),
                )
        return objects


@dataclass
class Xpra:
    display: str
    cmd: str
    options: str


@dataclass
class Tools:
    dmenu: str


@dataclass
class Pivot:
    box: "Box"


@dataclass
class Box:
    file: Optional[str]
    suffix: Optional[str]


config = Config()
