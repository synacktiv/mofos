from libvirt import (  # type: ignore
    virDomain,
    libvirtError,
    VIR_DOMAIN_AFFECT_LIVE,
    VIR_DOMAIN_AFFECT_CONFIG,
    VIR_DOMAIN_METADATA_ELEMENT,
    VIR_DOMAIN_RUNNING,
    VIR_DOMAIN_SHUTOFF,
)

from lxml import etree  # type: ignore
from os import remove, makedirs
from os.path import exists, join
from shlex import split as shlex_split
from time import sleep
from socket import AF_VSOCK, AF_INET, SOCK_STREAM, socket
from string import ascii_lowercase
from tempfile import mktemp
from typing import Any, Union, Iterator, Optional
from hashlib import sha3_224
from functools import cache

from json import load as json_load, dump as json_dump, JSONDecodeError

from mofos.lib.utils import error, local_run, local_exec, notify
from mofos.lib.common import libvirt_conn
from mofos.lib.spicex_client import SpiceXSession
from mofos.lib.pool import pool
from mofos.lib.volume import Volume
from mofos.settings import config as cnf, NET_HELPER, LIBVIRT_OS_VARIANTS, HOME, PROJECT


@cache
def get_all_domains() -> list["Domain"]:
    return [Domain(dom) for dom in libvirt_conn().listAllDomains()]


@cache
def get_all_virDomains() -> list[virDomain]:
    return [dom for dom in libvirt_conn().listAllDomains()]


@cache
def get_all_vms() -> list[str]:
    return list(map(lambda x: x.name(), get_all_virDomains()))


@cache
def get_running_domains() -> list["Domain"]:
    return list(
        map(
            lambda x: Domain(x.name()),
            filter(lambda x: x.state()[0] == VIR_DOMAIN_RUNNING, get_all_virDomains()),
        )
    )


@cache
def get_running_vms() -> list[str]:
    return list(
        map(
            lambda x: x.name(),
            filter(lambda x: x.state()[0] == VIR_DOMAIN_RUNNING, get_all_virDomains()),
        )
    )


@cache
def get_template_domains() -> list["Domain"]:
    return list(filter(lambda x: x.is_template(), get_all_domains()))


@cache
def get_shutoff_vms() -> list[str]:
    return list(
        map(
            lambda x: x.name(),
            filter(lambda x: x.state()[0] == VIR_DOMAIN_SHUTOFF, get_all_virDomains()),
        )
    )


def get_template_sshpubkey(kind: str, name: str) -> Optional[str]:
    sshpubkey: str
    try:
        with open(f"{HOME}/.local/share/{PROJECT}/ssh.json", "r") as fp:
            dic = json_load(fp)
            keys = dic.get(kind, {})
            sshpubkey = keys.get(name, None)
        return sshpubkey
    except FileNotFoundError:
        return None


def set_template_sshpubkey(kind: str, name: str, key: str) -> None:
    ssh_json_file = f"{HOME}/.local/share/{PROJECT}/ssh.json"
    makedirs(f"{HOME}/.local/share/{PROJECT}", exist_ok=True)
    if exists(ssh_json_file):
        with open(ssh_json_file, "r") as fp:
            keys = json_load(fp)
    else:
        keys = {}

    keys.setdefault(kind, {}).update({name: key})
    with open(ssh_json_file, "w") as fp:
        json_dump(keys, fp, indent=2)


# TODO: make it interface agnostic, 20250428, still needed?
def _get_dict_from_lease_file() -> list[Any]:
    libvirt_intf_file = f"{cnf.libvirt.dnsmasq_home}/{cnf.libvirt.interface}.status"

    if not exists(libvirt_intf_file):
        error(f"No lease file for interface: {cnf.libvirt.interface}")

    with open(libvirt_intf_file, "r") as fp:
        try:
            data = json_load(fp)
        except JSONDecodeError:
            data = []

    return data


def _get_vm_name_from_ip(ip: str) -> str:
    data = _get_dict_from_lease_file()

    elem = list(
        filter(lambda x: x["ip-address"] == ip if "ip-address" in x else {}, data)
    )

    if elem is not None and elem != []:
        mac = elem[0]["mac-address"]
        for lv in get_all_virDomains():
            root = etree.fromstring(lv.XMLDesc())
            m = root.xpath("/domain/devices/interface/mac/@address")
            if m and mac == m[0]:
                return lv.name()

    raise Domain.NotFound(f"{ip} does not correspond to an existing domain")


class Domain:
    @classmethod
    def from_ip(cls, ip: str):
        name = _get_vm_name_from_ip(ip)
        return Domain(name)

    @classmethod
    def new(
        cls,
        name: str,
        template: "Domain",
        network: str,
        shmem: bool = cnf.defaults.shmem,
        vsock: bool = cnf.defaults.vsock,
        cpus: int = cnf.defaults.cpus,
        ram: int = cnf.defaults.ram,
    ):
        variant = template.variant()
        if variant == "":
            raise Domain.InvalidTemplate("Template invalid: no variant found")

        if name in get_all_vms():
            raise Domain.AlreadyExists(f"{name} already exists")

        if template.os == "linux":
            # Taking template first volume as lower layer
            base_disk = template.volumes()[0]
            overlay_vol = Volume.from_name(cnf.defaults.overlay.disk)
            new_vol = overlay_vol.clone(f"{name}-disk.qcow2")
            disk = (
                f"--disk path={cnf.libvirt.disks}/{base_disk},readonly=on,shareable=on,bus=virtio "
                f"--disk path={new_vol.path} "
            )
        elif template.os == "windows":
            new_disk = f"{name}-disk.qcow2"
            backing_volume = Volume.from_name(f"{template}-disk.qcow2")
            backing_volume.clone_as_backing(new_disk)
            disk_bus = template.setting("/domain/devices/disk/target/@bus")[0]
            disk = f"--disk path={cnf.libvirt.disks}/{new_disk},bus={disk_bus} "

        if network == "none":
            network_arg = "none"
        else:
            net_model = template.setting("/domain/devices/interface/model/@type")[0]
            network_arg = f"network={network},model={net_model}"

        s_vsock = "--vsock cid.auto=yes" if vsock else ""
        s_shmem = (
            "--memorybacking source.type=memfd,access.mode=shared " if shmem else ""
        )
        ret, _, err = local_run(
            (
                "/usr/bin/virt-install "
                f"--name={name} --ram={ram} --vcpus={cpus} "
                f"{disk}"
                "--noautoconsole --graphics=spice --hvm --boot hd "
                f"--network {network_arg} "
                f"--os-variant={variant} {s_vsock} {s_shmem} "
                "--check path_in_use=off --import"
            ),
            want_output=True,
        )
        if ret:
            error(f"Could not create {name}: {err.decode('utf8')}")

        return Domain(name)

    # Attributes
    _xml_root: etree._Element
    xml: str
    name: str
    os: str
    lv: virDomain
    spicex_session: SpiceXSession
    managed: bool
    alias: str
    description: str
    tags: list[str]

    def __init__(self, input: Union[virDomain, str], kind: str = ""):
        if isinstance(input, virDomain):
            self.lv = input
            vm_name = self.lv.name()
        else:
            self.lv = libvirt_conn().lookupByName(input)
            vm_name = input

        self.xml = ""  # will only be instanciated when using settings
        self._xml_root = None  # will only be instanciated when using settings
        self.id = self.lv.ID()
        self.refresh_ip()
        self.name = vm_name
        self.os = "windows" if "microsoft" in self.variant() else "linux"
        self.distrib = LIBVIRT_OS_VARIANTS.get(self.variant(), "generic")
        # SpiceX session
        self.spicex_session = SpiceXSession(self.name, self.spice_port())
        self.description = ""
        self.alias = ""
        self.tags = []
        self.kind = kind

    def __str__(self):
        return self.name

    def is_template(self) -> bool:
        self.load_metadata()
        return self.kind == "template"

    def running(self) -> bool:
        return self.lv.state()[0] == VIR_DOMAIN_RUNNING

    def shutoff(self) -> bool:
        return self.lv.state()[0] == VIR_DOMAIN_SHUTOFF

    def start(self):
        if self.running():
            raise Domain.AlreadyRunningError(f"{self} is already running")
        self.lv.create()
        # Refreshing the XML with the running domain
        # self.xml = self.lv.XMLDesc()
        self._xml_root = None

    def poststart(self):
        self.load_metadata()
        if self.managed:
            for tag in self.tags:
                if tag not in cnf.hooks:
                    raise Domain.HookNotFoundError(
                        f"`{tag}` tag not defined in the configuration"
                    )
                if cnf.hooks[tag].start is None:
                    continue
                cmd = (
                    f"{cnf.hooks[tag].start} {tag} {self.name} "
                    f"{self.os} {self.distrib} {self.alias}"
                )
                err, _, _ = local_run(cmd)
                if err:
                    raise Domain.HookExecutionError(
                        f"An error occurred during the hook execution: {tag}"
                    )

    def _stop(self):
        if self.shutoff():
            raise Domain.NotRunningError(f"{self} is not running")
        if NET_HELPER and exists(NET_HELPER) and self.ip:
            local_run(f"/usr/bin/sudo {NET_HELPER} flush {self.ip}")
        # FIXME
        local_run(f"/usr/bin/systemctl --user stop vm-xpra@{self.name}")
        if self.spicex_session.started():
            self.spicex_session.stop()

    def stop(self):
        self._stop()
        self.lv.shutdown()

    def kill(self):
        self._stop()
        self.lv.destroy()

    @cache
    def state(self):
        status, _ = self.lv.state()
        if status == VIR_DOMAIN_RUNNING:
            return "running"
        elif status == VIR_DOMAIN_SHUTOFF:
            return "shutoff"

    def remove(self, volumes: list[Volume]):
        own_volumes = [v.name for v in self.volumes() if v]
        for vol in volumes:
            if vol.name not in own_volumes:
                raise Domain.UnassociatedVolume(
                    f"Volume {vol} not associated to {self}"
                )
            try:
                vol.remove()
            except Volume.DeleteError as e:
                raise Domain.RemoveError(e)
        try:
            self.lv.undefine()
        except libvirtError as e:
            raise Domain.RemoveError(e)

    @cache
    def volumes(self) -> list[Volume]:
        vol = []
        for file in self.storage_files():
            v = Volume.from_path(file)
            if v:
                vol.append(v)
        return vol

    def storage_files(self) -> list[str]:
        return self.setting("/domain/devices/disk/source/@file")

    def disks(self) -> list[str]:
        return self.setting("/domain/devices/disk/target/@dev")

    # @cache
    def vsock(self) -> int:
        vsock_conf = self.setting("/domain/devices/vsock/cid/@address")
        if vsock_conf:
            return int(vsock_conf[0])
        else:
            return 0

    def has_device(self, type, args) -> bool:
        if type == "usb":
            vendor_id, product_id = args
            result = self.setting(
                f"/domain/devices/hostdev/source[vendor[@id='0x{vendor_id}'] and product[@id='0x{product_id}']]"
            )
        elif type == "pci":
            domain, bus, slot, function = args
            result = self.setting(
                (
                    f"/domain/devices/hostdev[source/address/@domain='0x{domain}' "
                    f"and source/address/@bus='0x{bus}' "
                    f"and source/address/@slot='0x{slot}' "
                    f"and source/address/@function='0x{function}']"
                )
            )
        elif type == "fs":
            local_path, label = args
            result = self.setting(
                f"/domain/devices/filesystem[source/@dir='{local_path}' and target/@dir='{label}']"
            )
        return result != 0 and result != []

    def ensure_ip(self) -> str:
        if self.ip:
            return self.ip

        # refresh
        self.refresh_ip()
        if self.ip:
            return self.ip
        raise Domain.NoLeaseError(f"No lease registered for {self.name}")

    def refresh_ip(self):
        result = self.setting("/domain/devices/interface/mac/@address")
        if result == []:
            self.ip = None
            return

        mac = result[0]
        data = _get_dict_from_lease_file()

        elem = list(
            filter(
                lambda x: x["mac-address"] == mac if "mac-address" in x else False, data
            )
        )

        self.ip = elem[0]["ip-address"] if elem != [] else None

    def setting(self, xpath: str, ns: dict[str, str] = {}) -> list[str]:
        if self._xml_root is None:
            self.xml = self.lv.XMLDesc()
            self._xml_root = etree.fromstring(self.xml)
        return self._xml_root.xpath(xpath, namespaces=ns)

    def vnet(self, interface: str = "net0") -> Optional[str]:
        vnet = self.setting(
            f"/domain/devices/interface[alias/@name='{interface}']/target/@dev"
        )
        if len(vnet) == 0:
            return None

        return vnet[0]

    def spice_port(self) -> int:
        result = self.setting("/domain/devices/graphics/@port")
        if len(result) == 0:
            return 0

        return int(result[0])

    def load_metadata(self) -> None:
        namespaces = {
            "libosinfo": "http://libosinfo.org/xmlns/libvirt/domain/1.0",
            PROJECT: f"{PROJECT}://data",
        }
        managed = self.setting(
            f"/domain/metadata/{PROJECT}:data/@managed", ns=namespaces
        )
        self.managed = len(managed) > 0 and managed[0] == "yes"
        if managed:
            description = self.setting(
                f"/domain/metadata/{PROJECT}:data/{PROJECT}:description/text()",
                ns=namespaces,
            )
            self.description = description[0] if len(description) > 0 else ""

            alias = self.setting(
                f"/domain/metadata/{PROJECT}:data/{PROJECT}:alias/text()", ns=namespaces
            )
            self.alias = alias[0] if len(alias) > 0 else ""
            self.tags = self.setting(
                f"/domain/metadata/{PROJECT}:data/{PROJECT}:tags/{PROJECT}:tag/text()",
                ns=namespaces,
            )
            kind = self.setting(
                f"/domain/metadata/{PROJECT}:data/{PROJECT}:kind/text()",
                ns=namespaces,
            )
            if kind:
                self.kind = kind[0]
        else:
            self.description = ""
            self.alias = ""

    def set_metadata(self):
        flags = VIR_DOMAIN_AFFECT_CONFIG
        if self.running():
            flags |= VIR_DOMAIN_AFFECT_LIVE

        data = etree.Element("data", managed="yes")
        if self.description:
            description = etree.Element("description")
            description.text = self.description
            data.append(description)
        if self.alias:
            alias = etree.Element("alias")
            alias.text = self.alias
            data.append(alias)
        if self.kind:
            kind = etree.Element("kind")
            kind.text = self.kind
            data.append(kind)
        if self.tags:
            tags = etree.Element("tags")
            for one_tag in self.tags:
                tag = etree.Element("tag")
                tag.text = one_tag
                tags.append(tag)
            data.append(tags)
        xml = etree.tostring(data).decode("utf8")
        self.lv.setMetadata(
            VIR_DOMAIN_METADATA_ELEMENT, xml, PROJECT, f"{PROJECT}://data", flags=flags
        )
        self._xml_root = None

    @cache
    def variant(self) -> str:
        variant = self.setting(
            "/domain/metadata/*[local-name()='libosinfo']/*[local-name()='os']/@id",
        )
        if len(variant) < 1:
            return "generic"
        else:
            return variant[0]

    def get_mnt(self) -> Iterator[tuple[str, str]]:
        sources = self.setting("/domain/devices/filesystem/source/@dir")
        targets = self.setting("/domain/devices/filesystem/target/@dir")
        return zip(sources, targets)

    def mount(self, local_path, remote_destination, mount=True):
        label = sha3_224(local_path.encode("utf8")).hexdigest()[:36]

        if self.has_device("fs", (local_path, label)):
            raise Domain.DeviceAlreadyAttached(f"{local_path} already mounted")

        virtiofs_xml = f"""
        <filesystem type="mount" accessmode="passthrough">
          <driver type="virtiofs"/>
          <binary path="/usr/lib/qemu/virtiofsd"/>
          <source dir="{local_path}"/>
          <target dir="{label}"/>
        </filesystem>"""

        try:
            self.lv.attachDeviceFlags(virtiofs_xml, VIR_DOMAIN_AFFECT_LIVE)
        except Exception as e:
            if "Requested operation is not valid: Target already exists" not in str(e):
                raise (e)
        if mount:
            err, _, _ = self.exec(
                (
                    f"mkdir -p {remote_destination} && "
                    f'[ -z "$(ls -A {remote_destination})" ] && '
                    f"mount -t virtiofs {label} {remote_destination} || "
                    "false"
                ),
                user="root",
            )
            if err:
                raise Domain.FileSystemMountError(
                    f"Target destination is not empty (would not recommend), perform a manual mount with the label {label}"
                )
        return label

    def umount(self, local_path, remote_destination, umount=True):
        label = sha3_224(local_path.encode("utf8")).hexdigest()[:36]

        if not self.has_device("fs", (local_path, label)):
            raise Domain.DeviceNotAttached(f"{local_path} not mounted")

        virtiofs_xml = f"""
        <filesystem type="mount" accessmode="passthrough">
          <driver type="virtiofs"/>
          <binary path="/usr/lib/qemu/virtiofsd"/>
          <source dir="{local_path}"/>
          <target dir="{label}"/>
        </filesystem>"""

        if umount:
            ret, _, err = self.exec(
                f"umount {remote_destination}", user="root", want_output=True
            )
            if ret:
                raise Domain.FileSystemUnmountError(
                    f"Could not unmount {remote_destination} -> {err.decode('utf8').strip()}"
                )
        try:
            self.lv.detachDeviceFlags(virtiofs_xml, VIR_DOMAIN_AFFECT_LIVE)
        except Exception as e:
            if "Requested operation is not valid: Target already exists" not in str(e):
                raise (e)

        return label

    def attach_usb(self, vendor_id, product_id, force=True):
        xml = f"""
        <hostdev mode='subsystem' type='usb' managed='yes'>
            <source>
                <vendor id='0x{vendor_id}' />
                <product id='0x{product_id}' />
            </source>
        </hostdev>
        """
        if self.has_device("usb", (vendor_id, product_id)):
            if not force:
                raise Domain.DeviceAlreadyAttached(
                    f"{vendor_id}:{product_id} is already attached to {self.name}"
                )
        else:
            try:
                self.lv.detachDevice(xml)
            except libvirtError as e:
                if "device not found" not in str(e):
                    raise (e)
        self.lv.attachDeviceFlags(xml, VIR_DOMAIN_AFFECT_LIVE)

    def detach_usb(self, vendor_id, product_id):
        xml = f"""
        <hostdev mode='subsystem' type='usb' managed='yes'>
            <source>
                <vendor id='0x{vendor_id}' />
                <product id='0x{product_id}' />
            </source>
        </hostdev>
        """
        if not self.has_device("usb", (vendor_id, product_id)):
            raise Domain.DeviceNotAttached(
                f"{vendor_id}:{product_id} is not attached to {self.name}"
            )
        self.lv.detachDeviceFlags(xml, VIR_DOMAIN_AFFECT_LIVE)

    def attach_pci(self, domain, bus, slot, function, force=True):
        xml = f"""
        <hostdev mode='subsystem' type='pci' managed='yes'>
            <source>
                <address domain='0x{domain}' bus='0x{bus}' slot='0x{slot}' function='0x{function}' />
            </source>
        </hostdev>
        """
        if self.has_device("pci", (domain, bus, slot, function)):
            if not force:
                raise Domain.DeviceAlreadyAttached(
                    f"{domain}:{bus}:{slot}.{function} is already attached to {self.name}"
                )
        else:
            try:
                self.lv.detachDevice(xml)
            except libvirtError as e:
                if "device not found" not in str(e):
                    raise (e)
        self.lv.attachDeviceFlags(xml, VIR_DOMAIN_AFFECT_LIVE)

    def detach_pci(self, domain, bus, slot, function):
        xml = f"""
        <hostdev mode='subsystem' type='pci' managed='yes'>
            <source>
                <address domain='0x{domain}' bus='0x{bus}' slot='0x{slot}' function='0x{function}' />
            </source>
        </hostdev>
        """
        if not self.has_device("pci", (domain, bus, slot, function)):
            raise Domain.DeviceNotAttached(
                f"{domain}:{bus}:{slot}.{function} is not attached to {self.name}"
            )
        self.lv.detachDeviceFlags(xml, VIR_DOMAIN_AFFECT_LIVE)

    def proxy_cmd(self) -> str:
        cid = self.vsock()
        if cid:
            return (
                f"{cnf.runtime.vsock.socat_bin_path} - "
                f"VSOCK-CONNECT:{cid}:{cnf.runtime.vsock.ssh_port}"
            )
        else:
            ip = self.ensure_ip()
            return f"{cnf.runtime.vsock.socat_bin_path} - TCP:{ip}:{cnf.ssh.port}"

    def ssh_cmd(self, user: str = cnf.ssh.user, cmd: str = "") -> list[str]:
        proxy_opts = f'ProxyCommand="{self.proxy_cmd()}"'
        ssh_options = f"-o {proxy_opts} -e none -i {cnf.ssh.key} -l {user} {self.name}"
        ssh = cnf.ssh.cmd
        if cmd:
            return shlex_split(ssh) + shlex_split(ssh_options) + [cmd]
        else:
            return shlex_split(ssh) + shlex_split(ssh_options)

    def exec(
        self,
        command: str,
        user: str = cnf.ssh.user,
        input: bytes = b"",
        want_output: bool = False,
    ) -> tuple[int, bytes, bytes]:
        self.init_controlmaster(user=user)
        return local_run(self.ssh_cmd(user, command), input, want_output)

    def ssh(self, user: str = cnf.ssh.user) -> None:
        self.init_controlmaster(user=user)
        local_exec(self.ssh_cmd(user))

    def sftp(self, user: str = cnf.ssh.user) -> None:
        proxy_opts = f'ProxyCommand="{self.proxy_cmd()}"'
        sftp = f"/usr/bin/sftp -o {proxy_opts} -i {cnf.ssh.key} {user}@{self.name}"
        self.init_controlmaster(user=user)
        local_exec(sftp)

    def scp(
        self,
        source: str,
        destination: str,
        user: str = cnf.ssh.user,
        is_dir: bool = False,
        push: bool = False,
        remote: Optional["Domain"] = None,
    ) -> None:
        proxy_opts = f'ProxyCommand="{self.proxy_cmd()}"'
        recurse = " -r" if is_dir else ""
        target: str
        scp_opts = (
            f"/usr/bin/scp -o {proxy_opts} -i {cnf.ssh.key} "
            f"{cnf.ssh.options}{recurse}"
        )
        if push:
            target = f"{source} {user}@{self.name}:{destination}"
        else:
            if remote:
                destination = f"{user}@{remote.name}:{destination}"
            target = f"{user}@{self.name}:{source} {destination}"

        self.init_controlmaster(user=user)
        local_exec(f"{scp_opts} {target}")

    def graphics(self, kind: str, user: str = cnf.ssh.user) -> None:
        if kind == "xpra":
            connection_string = f"ssh:{user}@{self.name}:{cnf.xpra.display}"
            self.init_controlmaster(user=user)
            local_exec(
                f"{cnf.xpra.cmd} {cnf.xpra.options} {connection_string} "
                f"--ssh 'ssh {cnf.ssh.options} "
                f'-o ProxyCommand="{self.proxy_cmd()}" '
                f"-i {cnf.ssh.key}'"
            )

    def add_disk(self, name, size, destination="", mount=True):
        # Ext2 does not support long label
        if len(name) > 16:
            error("Ext2/3/4 label can only have a length < 16 bytes")
        indices = self.disks()
        candidates = map(lambda x: f"vd{x}", ascii_lowercase)
        try:
            device = next(x for x in candidates if x not in indices)
        except StopIteration:
            error(f"No more virtual device index available for {self}")

        disk_name = f"{self.name}-{name}-disk.qcow2"
        disk_path = f"{cnf.libvirt.disks}/{disk_name}"
        unit = size[-1]
        size = size[:-1]

        storage_xml = f"""
        <volume>
​         <name>{disk_name}</name>
​         <allocation>0</allocation>
​         <capacity unit="{unit}">{size}</capacity>
​         <target>
            <format type='qcow2'/>
​           <path>{disk_path}</path>
​         </target>
    ​   </volume>"""
        vol = pool().new_volume(storage_xml)
        if not vol:
            error(f"Failed to create the volume {disk_name}")

        temp = mktemp()
        local_run(
            (
                f"virsh vol-download --pool {cnf.libvirt.pool} "
                f"--vol {disk_name} "
                f"--file {temp}"
            )
        )

        local_run(
            (
                "/usr/bin/virt-format --filesystem=ext4 --format=qcow2 "
                f"--label={name} -a {temp}"
            )
        )
        local_run(
            (
                f"virsh vol-upload --pool {cnf.libvirt.pool} "
                f"--vol {disk_name} --file {temp}"
            )
        )
        remove(temp)

        disk_xml = f"""
        <disk type="file" device="disk">
            <driver name="qemu" type="qcow2"/>
            <source file="{disk_path}"/>
            <backingStore/>
            <target bus="virtio" dev="{device}" />
        </disk>"""

        self.lv.attachDeviceFlags(
            disk_xml, VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG
        )

        if destination and mount:
            err, _, _ = self.exec(
                (
                    f"mkdir -p {destination} && "
                    f"echo 'LABEL={name} {destination} ext4 defaults 0 0' >> /etc/fstab && "
                    "systemctl daemon-reload && "
                    f"mount {destination}"
                ),
                user="root",
            )
            if err:
                error(f"Failed to update /etc/fstab on {self}")

    def change_template_disk(self, disk: str) -> None:
        current_template_disk = self.storage_files()[0]
        current_template_dev = self.disks()[0]
        disk_xml = f"""
        <disk type="file" device="disk">
            <driver name="qemu" type="qcow2"/>
            <source file="{current_template_disk}"/>
            <backingStore/>
            <readonly/>
            <shareable/>
            <target bus="virtio" dev="{current_template_dev}" />
        </disk>"""
        self.lv.detachDeviceFlags(disk_xml, VIR_DOMAIN_AFFECT_CONFIG)
        new_disk_xml = f"""
        <disk type="file" device="disk">
            <driver name="qemu" type="qcow2"/>
            <source file="{disk}"/>
            <backingStore/>
            <readonly/>
            <shareable/>
            <target bus="virtio" dev="{current_template_dev}" />
        </disk>"""
        self.lv.attachDeviceFlags(new_disk_xml, VIR_DOMAIN_AFFECT_CONFIG)

    def wait(self, timeout: int = 30, init_control_master: bool = True) -> bool:
        def wait_for_ip():
            k = 0
            while self.ip is None and k < timeout:
                k += 1
                sleep(1)
                self.refresh_ip()

            if self.ip is None:
                notify("Critical", f"No IP address for {self}")
                return False
            return True

        if not self.vsock():
            has_an_ip = wait_for_ip()
            if not has_an_ip:
                return False

        # Waiting for a valid connection with the virtual machine
        k = 0
        sock = None
        while k < timeout:
            k += 1
            try:
                if self.vsock():
                    sock = socket(AF_VSOCK, SOCK_STREAM)
                    peer = (self.vsock(), cnf.runtime.vsock.ssh_port)
                else:
                    sock = socket(AF_INET, SOCK_STREAM)
                    peer = (self.ip, cnf.ssh.port)

                sock.settimeout(1)
                sock.connect(peer)
                sock.close()
                break
            except OSError:
                sleep(1)
                continue
        if k >= timeout:
            notify("Critical", f"{self} not accesible")
            return False
        else:
            if init_control_master:
                if not self.init_controlmaster(force=True, timeout=timeout - k):
                    notify("Critical", f"SSH access to {self} impossible")
                    return False

            notify("Low", f"{self} is ready")
            return True

    def has_controlmaster(self, user: str = cnf.ssh.user) -> bool:
        return exists(
            join(
                cnf.ssh.controlmaster.path,
                f"{user}@{self.name}:{cnf.ssh.port}",
            )
        )

    def init_controlmaster(
        self, user: str = cnf.ssh.user, force: bool = False, timeout: int = 30
    ) -> bool:
        # Create the folder containing control master sockets
        if not exists(cnf.ssh.controlmaster.path):
            makedirs(cnf.ssh.controlmaster.path, exist_ok=True)

        if self.has_controlmaster(user=user):
            if force:
                remove(
                    join(
                        cnf.ssh.controlmaster.path,
                        f"{user}@{self.name}:{cnf.ssh.port}",
                    )
                )
            else:
                return True

        err = 0xFF
        k = 0
        while k < timeout and err != 0x00:
            k += 1
            err, _, _ = local_run(
                (
                    f"{cnf.ssh.cmd} -o ControlMaster=yes -o ControlPersist=yes "
                    f"-o 'ProxyCommand={self.proxy_cmd()}' "
                    f"-i {cnf.ssh.key} -l {user} {self.name} -- exit"
                ),
                daemon=True,
            )
            sleep(1)
        return err == 0x00

    class AlreadyExists(Exception):
        pass

    class InvalidTemplate(Exception):
        pass

    class NoLeaseError(Exception):
        pass

    class AlreadyRunningError(Exception):
        pass

    class DeviceAlreadyAttached(Exception):
        pass

    class DeviceNotAttached(Exception):
        pass

    class NotRunningError(Exception):
        pass

    class RemoveError(Exception):
        pass

    class NotFound(Exception):
        pass

    class UnassociatedVolume(Exception):
        pass

    class FileSystemMountError(Exception):
        pass

    class FileSystemUnmountError(Exception):
        pass

    class SpiceError(Exception):
        pass

    class HookExecutionError(Exception):
        pass

    class HookNotFoundError(Exception):
        pass
