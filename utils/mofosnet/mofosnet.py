#!/usr/bin/env python3

import click

from tomllib import load as toml_load
from ipaddress import ip_address, IPv4Address, IPv4Network
from subprocess import run, Popen, PIPE
from shlex import split as shlex_split
from sys import stdout
from re import search, match
from os import kill, unlink, getuid, environ, umask
from os.path import exists
from signal import SIGTERM
from pyroute2 import IPRoute  # type: ignore
from json import dump, load, JSONDecodeError
from functools import wraps
from libvirt import open as libvirt_open  # type: ignore
from uuid import uuid4
from typing import Any, List, Dict
from dataclasses import dataclass

QEMU_CONNECTION = "qemu:///system"


@click.group()
def cli():
    pass


def __get_tun_id() -> int:
    """
    Return the next available tun identifier
    """
    tun_ifaces = []
    with IPRoute() as ip:
        for iface in ip.get_links():
            name = ""
            altname = ""
            link_info = iface.get_attrs("IFLA_LINKINFO")
            if link_info:
                kind = link_info[0].get_attrs("IFLA_INFO_KIND")[0]
                if kind == "tun":
                    proplist = iface.get_attrs("IFLA_PROP_LIST")
                    if proplist:
                        altname = proplist[0].get_attrs("IFLA_ALT_IFNAME")[0]
                    name = iface.get_attrs("IFLA_IFNAME")[0]
                    if name.startswith("tun"):
                        tun_ifaces.append(name)
                    elif altname and altname.startswith("tun"):
                        tun_ifaces.append(altname)
    index = next((k for k in range(50) if f"tun{k}" not in tun_ifaces))
    return index


def __get_local_addr() -> str:
    with IPRoute() as ip:
        return ip.get_routes(
            dst=ip.get_routes(table=254)[0].get_attrs("RTA_GATEWAY")[0]
        )[0].get_attrs("RTA_PREFSRC")[0]


def __get_tun_id_from_dest(dest: str) -> int:
    with open(cnf.tunneling.run_file, "r") as fp:
        try:
            tun_dict = load(fp)
        except JSONDecodeError:
            exit(1)
    return tun_dict[dest]


def __get_dest_from_tun_id(id: int) -> str:
    with open(cnf.tunneling.run_file, "r") as fp:
        try:
            tun_dict = load(fp)
        except JSONDecodeError:
            exit(1)
    for key, val in tun_dict.items():
        if int(val) == id:
            break
    else:
        return ""
    return key


def __is_vnet_valid(vnet: str) -> None:
    with IPRoute() as ip:
        master = ip.link_lookup(ifname=cnf.libvirt.iface)
        if len(master) == 0:
            raise SystemError(f"{cnf.libvirt.iface} does not exist")
        master = master[0]
        vnet_iface = ip.link_lookup(ifname=vnet)
        if len(vnet_iface) == 0:
            raise SystemError(f"{vnet} does not exist")
        vnet_master = ip.get_links(vnet_iface[0])[0].get_attrs("IFLA_MASTER")
        if len(vnet_master) == 0:
            raise SystemError(f"{vnet} has not master")
        if master != vnet_master[0]:
            raise SystemError(f"{cnf.libvirt.iface} is not the master of {vnet}")


def require_root(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if getuid() != 0:
            raise click.ClickException("This command must be run as root")
        return func(*args, **kwargs)

    return wrapper


class IpAddress(click.ParamType):
    name = "IpAddress"

    def convert(self, value, param, ctx):
        if isinstance(value, str):
            ip = ip_address(value)
            if ip not in cnf.libvirt.dhcp_range:
                self.fail(f"{value} should be in the range: {cnf.libvirt.dhcp_range}")
            return ip
        self.fail(f"{value} is not a valid IP address")


class Gateway(click.ParamType):
    name = "Gateway"

    def convert(self, value, param, ctx):
        if isinstance(value, str):
            ip = ip_address(value)
            return ip
        self.fail(f"{value} is not a valid IP address")


@cli.command()
@click.argument("src_ip", type=IpAddress())
@click.argument("gateway", type=Gateway())
@require_root
def route(src_ip: IPv4Address, gateway: IPv4Address) -> None:
    """
    Create an IP rule that routes the source IP through the provided gateway.
    """
    table_id = int(str(src_ip).split(".")[3])
    with IPRoute() as ip:
        ip.flush_routes(table=table_id)
        ip.flush_rules(table=table_id)
        ip.rule("add", table=table_id, iifname=cnf.libvirt.iface, src=str(src_ip))

        ip.route("add", gateway=str(gateway), table=table_id)
        # Add custom routes into the new table
        for route in cnf.tunneling.routes:
            route_gateway = ip.get_routes(dst=route)[0].get_attrs("RTA_GATEWAY")[0]
            ip.route("add", dst=route, gateway=route_gateway, table=table_id)


@cli.command()
@click.argument("src_ip", type=IpAddress())
@require_root
def flush(src_ip: IPv4Address) -> None:
    """
    Flush the configuration for the source IP.
    """
    table_id = int(str(src_ip).split(".")[3])
    with IPRoute() as ip:
        ip.flush_routes(table=table_id)
        ip.flush_rules(table=table_id)


@cli.group()
@require_root
def tun() -> None:
    """
    Manage the local tun to perform SSH tunneling.
    """
    pass


@tun.command()
@click.argument("dest", type=str)
def add(dest: str) -> None:
    """
    Create a local tun with named related to the destination.
    """
    if exists(cnf.tunneling.run_file):
        with open(cnf.tunneling.run_file, "r") as fp:
            try:
                tun_dict = load(fp)
            except JSONDecodeError:
                tun_dict = {}
    else:
        tun_dict = {}

    if dest in tun_dict:
        exit(0)

    id = __get_tun_id()
    tun_name = f"{cnf.tunneling.tun_prefix}{id}"

    tun_dict[dest] = id

    with IPRoute() as ip:
        local_addr = __get_local_addr()
        suffix = local_addr.split(".")[3]
        local_addr = f"172.31.{suffix}.{id * 4 + 1}"

        if not ip.link_lookup(ifname=tun_name):
            ip.link("add", ifname=tun_name, kind="tuntap", mode="tun")
            ip.link("property_add", ifname=tun_name, altname=f"tun{id}")
        dev = ip.link_lookup(ifname=tun_name)[0]

        if not ip.get_addr(index=dev):
            ip.addr("add", label=tun_name, index=dev, mask=30, address=local_addr)

        ip.link("set", index=dev, state="up")

    with open(cnf.tunneling.run_file, "w") as fp:
        dump(tun_dict, fp, indent=4)


@tun.command()
@click.argument("dest", type=str)
def rm(dest: str) -> None:
    """
    Remove the tun corresponding to the provided destination.
    """
    with open(cnf.tunneling.run_file, "r") as fp:
        try:
            tun_dict = load(fp)
        except JSONDecodeError:
            exit(1)

    id = tun_dict[dest]
    tun_name = f"{cnf.tunneling.tun_prefix}{id}"

    with IPRoute() as ip:
        dev = ip.link_lookup(ifname=tun_name)
        if dev:
            ip.link("delete", index=dev[0])

    with open(cnf.tunneling.run_file, "w") as fp:
        tun_dict.pop(dest)
        dump(tun_dict, fp, indent=4)


@cli.group()
def sshvpn() -> None:
    """
    Manage the process establishing the SSH tunneling.
    """
    pass


@sshvpn.command()
@click.argument("dest", type=str)
def start(dest: str) -> None:
    """
    Establish a SSH connection to first create a remote tun and then link it to
    an existing local one.
    """
    if "SSH_AUTH_SOCK" not in environ:
        raise click.ClickException(
            "This command requires the configuration of a ssh-agent"
        )
    ssh_cmd = "/usr/bin/ssh -4akTx -S none"

    id = __get_tun_id_from_dest(dest)

    suffix: str = ""
    local_addr = __get_local_addr()
    suffix = local_addr.split(".")[3]

    # check whether a process with the same ID is already running
    pid_file = f"{cnf.tunneling.pid_file}_{id}.pid"
    if exists(pid_file):
        with open(pid_file, "r") as fp:
            pid = int(fp.read().strip())
            try:
                kill(pid, 0)
            except ProcessLookupError:
                unlink(pid_file)
            else:
                return

    remote_addr = f"172.31.{suffix}.{id * 4 + 2}"

    ssh_cmd = "/usr/bin/ssh -4akTx -S none"
    cmd = f"{ssh_cmd} {dest} {cnf.tunneling.command.start} {remote_addr}"
    ssh_proc = run(shlex_split(cmd), capture_output=True)
    remote_id = ssh_proc.stdout.strip().decode("utf8")

    ssh_options = "-oServerAliveInterval=30 -oExitOnForwardFailure=yes"
    cmd = f"{ssh_cmd} {ssh_options} -w {id}:{remote_id} {dest}"
    ssh_tun_proc = Popen(shlex_split(cmd), stdout=PIPE, stderr=PIPE)
    with open(f"{cnf.tunneling.pid_file}_{id}.pid", "w") as fp:
        fp.write(str(ssh_tun_proc.pid))

    try:
        ssh_tun_proc.communicate()
    except (Exception, KeyboardInterrupt):
        unlink(f"{cnf.tunneling.pid_file}_{id}.pid")
        cmd = f"{ssh_cmd} {dest} {cnf.tunneling.command.stop}"
        run(shlex_split(cmd), capture_output=False)


@sshvpn.command()
@click.argument("dest", type=str)
def stop(dest: str):
    """
    Terminate the process maintaining the SSH tunneling.
    """
    id = __get_tun_id_from_dest(dest)
    ssh_cmd = "/usr/bin/ssh -4akTx -S none"
    with open(f"{cnf.tunneling.pid_file}_{id}.pid", "r") as fp:
        pid = int(fp.read().strip())

        try:
            kill(pid, SIGTERM)
        except ProcessLookupError:
            pass
        unlink(f"{cnf.tunneling.pid_file}_{id}.pid")
        cmd = f"{ssh_cmd} {dest} {cnf.tunneling.command.stop}"
        run(shlex_split(cmd), capture_output=False)


@cli.command()
@click.argument("dest", type=str)
def gateway(dest: str) -> None:
    """
    Return the gateway to access the destination.
    """
    id = __get_tun_id_from_dest(dest)
    local_addr = __get_local_addr()
    suffix = local_addr.split(".")[3]
    print(f"172.31.{suffix}.{id * 4 + 2}")


@cli.command()
def list() -> None:
    """
    List the tunnel information.
    """
    result = {}
    with IPRoute() as ip:
        # Routes
        routes = []
        for route in ip.get_routes():
            # only process default gateways and non default table
            if route.get_attrs("RTA_DST") or route["table"] >= 254:
                continue
            gw = route.get_attrs("RTA_GATEWAY")[0]
            oif = route.get_attrs("RTA_OIF")
            if oif:
                ifindex = ip.link_lookup(index=oif[0])[0]
                ifname = ip.get_links(ifindex)[0].get_attr("IFLA_IFNAME")
            match = search(r"\d+$", ifname)
            if match is None:
                continue
            id = int(match.group(0))
            dest = __get_dest_from_tun_id(id)
            routes.append({"id": route["table"], "gw": gw, "dev": ifname, "dest": dest})

        # Devices
        devices = []
        for link in ip.get_links():
            ifname = link.get_attr("IFLA_IFNAME")
            if not ifname.startswith(cnf.tunneling.tun_prefix):
                continue

            ifindex = link["index"]
            ifalias = link.get_attr("IFLA_PROP_LIST").get_attr("IFLA_ALT_IFNAME")
            state = link.get_attr("IFLA_OPERSTATE")
            if ifalias is None:
                ifalias = "None"
            addrs = ip.get_addr(index=ifindex)
            ip_addresses = [addr.get_attr("IFA_ADDRESS") for addr in addrs]
            devices.append(
                {
                    "name": ifname,
                    "index": ifindex,
                    "alt": ifalias,
                    "state": state,
                    "ip": ip_addresses,
                }
            )
        # Rules
        rules = []
        for rule in ip.get_rules():
            iif = rule.get_attrs("FRA_IIFNAME")
            if not iif or iif[0] != cnf.libvirt.iface:
                continue
            prio = rule.get_attrs("FRA_PRIORITY")[0]
            src = rule.get_attrs("FRA_SRC")[0]
            rules.append(
                {"iif": iif[0], "prio": prio, "src": src, "table": rule["table"]}
            )

        result["routes"] = routes
        result["devices"] = devices
        result["rules"] = rules

    dump(result, stdout, indent=4)


@cli.group()
@require_root
def network() -> None:
    """
    Manage virtual networks.
    """
    pass


@network.command()
@click.argument("name", type=str)
@click.option(
    "--pxe_root",
    type=click.Path(exists=True, dir_okay=True),
    help="tftp root for PXE boots.",
)
def create(name: str, pxe_root: str) -> None:
    """
    Create a new Libvirt network
    """
    if not match(r"\w+", name):
        raise SystemError("Invalid name")

    lv = libvirt_open(QEMU_CONNECTION)
    k = 1

    for net in lv.listAllNetworks():
        if net.name().startswith(name):
            k += 1
    net_name = f"{name}-{k:02d}"
    net_uuid = uuid4()
    net_prefix = f"192.168.{90 + k}"
    net_mask = "255.255.255.0"
    bootp_file = "pxelinux.0"
    net_gateway = f"{net_prefix}.1"

    xml = f"""
<network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0' connections='1'>
    <name>{net_name}</name>
    <uuid>{net_uuid}</uuid>
    <bridge name='{net_name}' stp='off' delay='0' />
    <forward mode='open' />
    <ip address='{net_gateway}' netmask='{net_mask}'>
        <tftp root='{pxe_root}' />
        <dhcp>
          <range start='{net_prefix}.10' end='{net_prefix}.254' />
          <bootp file='{bootp_file}' />
        </dhcp>
    </ip>
</network>
"""
    network = lv.networkDefineXML(xml)
    network.create()
    dump({"name": net_name, "gateway": net_gateway}, stdout)


@network.command("destroy")
@click.argument("name", type=str)
def destroy_libvirt_iface(name: str) -> None:
    """
    Destroy an existing Libvirt network
    """

    if not match(r"\w+-\d{2}", name):
        raise SystemError("Invalid name")

    lv = libvirt_open(QEMU_CONNECTION)
    # Raises exceptions
    network = lv.networkLookupByName(name)
    network.destroy()
    network.undefine()


@cli.group()
@require_root
def firewall() -> None:
    "Manage the isolation of managed virtual machines."
    pass


@firewall.command()
@click.argument("domain")
@click.argument("vnet")
def reset(domain: str, vnet: str) -> None:
    """
    Reset the firewall of the given domain.
    """
    if not cnf.firewall.enable:
        return None

    __is_vnet_valid(vnet)

    nft_rule = (
        f"table bridge filter-{domain} {{ }}\n"
        f"flush table bridge filter-{domain}\n"
        f"table bridge filter-{domain} {{\n"
        "\tchain forward {\n"
        "\t\ttype filter hook forward priority 0; policy accept;\n"
        f'\t\tiifname "{vnet}" drop\n'
        "\t}\n"
        "}"
    )
    run(shlex_split("nft -f -"), input=nft_rule.encode("utf8"))


@firewall.command("destroy")
@click.argument("domain")
@click.argument("vnet")
def destroy_fw_table(domain: str, vnet: str) -> None:
    """
    Reset the firewall of the given domain.
    """
    if not cnf.firewall.enable:
        return None

    __is_vnet_valid(vnet)

    nft_cmd = f"nft delete table bridge filter-{domain}"
    run(shlex_split(nft_cmd))


@firewall.command("allow")
@click.argument("src_domain")
@click.argument("src_vnet")
@click.argument("dst_domain")
@click.argument("dst_vnet")
def allow(src_domain: str, src_vnet: str, dst_domain: str, dst_vnet: str) -> None:
    """
    Allow two domains to communicate with each other.
    """
    if not cnf.firewall.enable:
        return None

    __is_vnet_valid(src_vnet)
    __is_vnet_valid(dst_vnet)

    src_nft = f"nft insert rule bridge filter-{src_domain} forward iifname {src_vnet} oifname {dst_vnet} counter accept"
    dst_nft = f"nft insert rule bridge filter-{dst_domain} forward iifname {dst_vnet} oifname {src_vnet} counter accept"
    run(shlex_split(src_nft))
    run(shlex_split(dst_nft))


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
            with open("/etc/mofos/mofosnet.toml", "rb") as fp:
                self.cnf = toml_load(fp)
        except FileNotFoundError:
            self.cnf = {}

        if "XDG_RUNTIME_DIR" in environ:
            pid_file_prefix = environ["XDG_RUNTIME_DIR"]
        else:
            pid_file_prefix = ""

        self.libvirt = Config.Libvirt(
            self.get("libvirt.iface", "mof0"),
            IPv4Network(self.get("dhcp_range", "192.168.90.128/25")),
        )
        self.tunneling = Config.Tunneling(
            self.get("tunneling.tun_prefix", "sshvpn"),
            self.get("tunneling.tun_dest_regexp", ".*"),
            self.get("tunneling.routes", []),
            Config.Command(
                self.get("tunneling.command.start", ""),
                self.get("tunneling.command.stop", ""),
            ),
            self.get("tunneling.run_file", "/run/mofosnet.json"),
            self.get(
                "tunneling.pid_file",
                f"{pid_file_prefix}/{self.get('tunneling.tun_prefix', 'sshvpn')}",
            ),
        )
        self.firewall = Config.Firewall(self.get("firewall.enable", False))

    @dataclass
    class Libvirt:
        iface: str
        dhcp_range: IPv4Network

    @dataclass
    class Command:
        start: str
        stop: str

    @dataclass
    class Tunneling:
        tun_prefix: str
        tun_dest_regexp: str
        routes: List[str]
        command: "Config.Command"
        run_file: str
        pid_file: str

    @dataclass
    class Firewall:
        enable: bool


if __name__ == "__main__":
    umask(0o22)
    cnf = Config()
    cli()
