import click
import logging

from os import environ

from lxml import etree  # type: ignore

from mofos.lib.commands.main import __main__
from mofos.lib.common import libvirt_conn
from mofos.lib.kinds import Type, need_ssh_agent, autocomplete
from mofos.lib.utils import error, local_run
from mofos.lib.domain import Domain, get_running_domains
from mofos.lib.logger import VmLogger
from mofos.settings import config as cnf
from mofos.settings import NET_HELPER

log: VmLogger = logging.getLogger(__name__)  # type: ignore


def _create_tunnel(domain: Domain, dest: str):
    err, _, _ = local_run(f"/usr/bin/sudo {NET_HELPER} tun add {dest}")
    if err:
        error(f"Could not create the local tun for {dest}")
    err, gateway, _ = local_run(f"{NET_HELPER} gateway {dest}", want_output=True)
    if err:
        error(f"Could not retrieve the host gateway for {dest}")
    gw = gateway.strip().decode("utf8")
    err, _, _ = local_run(f"/usr/bin/sudo {NET_HELPER} route {domain.ip} {gw}")
    if err:
        error(f"Could not configure the route between {domain.ip} and {gw}")
    log.debug("The tunnel establishment requires the ssh-agent to be unlocked")
    prop: str = ""
    if "SSH_AUTH_SOCK" in environ:
        prop = f"--property=Environment=SSH_AUTH_SOCK={environ['SSH_AUTH_SOCK']}"
    err, _, _ = local_run(
        (
            f"/bin/systemd-run --user --collect --unit sshvpn-{dest} "
            f"--property=Restart=on-failure {prop} "
            f"--description='SSH VPN to {dest}' "
            f"-- {NET_HELPER} sshvpn start {dest}"
        )
    )
    if err:
        error("Could not start the sshvpn transient service")


def _delete_tunnel(domain: Domain, dest: str):
    err, _, _ = local_run(f"systemctl --user stop sshvpn-{dest}")
    if err:
        error("Could not stop the ssh tunnel systemd service")
    err, _, _ = local_run(f"{NET_HELPER} sshvpn stop {dest}")
    if err:
        error("Could not stop the ssh tunnel")
    err, _, _ = local_run(f"/usr/bin/sudo {NET_HELPER} flush {domain.ip}")
    if err:
        error(f"Could not flush the route configured for {domain.ip}")
    err, _, _ = local_run(f"/usr/bin/sudo {NET_HELPER} tun rm {dest}")
    if err:
        error(f"Could not remove the local tun for {dest}")


def _get_libvirt_net_gateway() -> str:
    network = libvirt_conn().networkLookupByName(cnf.libvirt.network)
    xml = network.XMLDesc()
    xml_root = etree.fromstring(xml)
    ip = xml_root.xpath("/network/ip/@address")
    if len(ip) > 0:
        return ip[0]
    else:
        raise Exception("Could not retrieve the bridge IP address")


def _configure_gateway(
    domain: Domain, gateway: str = "", target: str = "", remove: bool = False
) -> None:
    log.debug(target)
    if domain.os == "windows":
        if target:
            netmask = "255.255.255.255"
        else:
            target = "0.0.0.0"
            netmask = "0.0.0.0"

        if not remove:
            command = f"route add {target} mask {netmask} {gateway}"
        else:
            command = f"route delete {target} mask {netmask} {gateway}"
        err, _, _ = domain.exec(command, user="user")
        if err:
            raise Exception(f"Could not configure {domain} default gateway")
    else:
        if not target:
            target = "default"
        if not remove:
            command = (
                f"/bin/ip route add {target} via {gateway} proto static metric 1024"
            )
        else:
            # We don't know which gateway to remove, so we remove them all
            if gateway == "":
                command = f"/bin/ip route {target} default"
            else:
                command = f"/bin/ip route delete {target} via {gateway} proto static metric 1024"
        err, _, _ = domain.exec(command, "root")
        if err:
            raise Exception(f"Could not configure {domain} default gateway")


def _configure_dns(domain, dns="", remove=False):
    if dns or remove:
        if domain.os == "windows":
            user = "user"
            if not remove:
                command = f"Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter).Name -ServerAddresses {dns}"
            else:
                command = "Set-DnsClientServerAddress -InterfaceAlias (Get-NetAdapter).Name -ResetServerAddresses"
        else:
            user = "root"
            if not remove:
                command = f"echo nameserver {dns} > /etc/resolv.conf"
            else:
                command = "echo > /etc/resolv.conf"

        domain.exec(command, user=user)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def ip(domain: Domain):
    """
    Retrieve the target domain IP address.
    """
    if domain.ip:
        print(domain.ip)
    else:
        raise SystemExit(1)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("gateway", type=click.STRING)
@click.option(
    "-f", "--force", is_flag=True, help="Override the current default gateway"
)
@click.option("-d", "--dns", type=click.STRING, help="DNS server to configure")
@need_ssh_agent
def route(domain: Domain, gateway: str, force: bool = False, dns: str = ""):
    """
    Route the domain to the given gateway reachable by the host: the host routes
    the domain toward the given gateway via ip rule.
    """
    ip = domain.ensure_ip()
    local_gateway = _get_libvirt_net_gateway()

    if gateway == "flush":
        log.debug(f"Flushing {domain} default gateway and local routing table'")
        err, _, _ = local_run(f"/usr/bin/sudo {NET_HELPER} flush {ip}")
        if err:
            error("Could not flush the routing configuration applied to {ip}")
        _configure_gateway(domain, gateway=local_gateway, remove=True)
        _configure_dns(domain, remove=True)

    else:
        log.debug(f"Configuring {domain} default gateway to {gateway} through {ip}'")
        err, _, _ = local_run(f"/usr/bin/sudo {NET_HELPER} route {ip} {gateway}")
        if err:
            error(f"Could not configure the route between {ip} and {gateway}")
        if force:
            log.debug(f"Overriding {domain}'s default gateway")
            _configure_gateway(domain, gateway="", remove=True)
        _configure_gateway(domain, gateway=local_gateway)
        _configure_dns(domain, dns)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("hop", type=Type.domain, shell_complete=autocomplete("running"))
@click.option(
    "-f", "--force", is_flag=True, help="Override the current default gateway"
)
@click.option("-d", "--dns", type=click.STRING, help="DNS server to configure")
@click.option("-t", "--target", type=click.STRING, help="Target IP to route for")
@need_ssh_agent
def pivot(
    domain: Domain, hop: Domain, force: bool = False, dns: str = "", target: str = ""
):
    """
    Route the domain to the given virtual machine.
    Local configuration of the new hop is to be manually set up.
    If target is not provided, the default gateway of the domain is modified
    """
    gw = hop.ensure_ip()
    if force:
        try:
            log.debug("Try to remove the current default gateway")
            _configure_gateway(domain, gateway="", target=target, remove=True)
        except Exception as e:
            log.warning(e)
    _configure_gateway(domain, gateway=gw, target=target)
    _configure_dns(domain, dns)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@need_ssh_agent
def net_flush(domain: Domain):
    """
    Flush the default gateway and the DNS configuration of the target domain.
    """
    log.debug(f"Flushing {domain} default gateway and local routing table'")
    err, _, _ = local_run(f"/usr/bin/sudo {NET_HELPER} flush {ip}")
    if err:
        error("Could not flush the routing configuration applied to {ip}")
    _configure_gateway(domain, gateway="", remove=True)
    _configure_dns(domain, remove=True)


@__main__.command()
@click.argument("action", type=click.Choice(["start", "stop"]))
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("destination", shell_complete=autocomplete("boxes"))
@click.option("-d", "--dns", type=click.STRING, help="DNS server to configure")
@click.option(
    "-f", "--force", is_flag=True, help="Override the current default gateway"
)
@need_ssh_agent
def tunnel(
    action: str, domain: Domain, destination: str, dns: str = "", force: bool = False
):
    """
    Establish a SSH-VPN tunnel and route the domain through it.
    """
    local_gateway = _get_libvirt_net_gateway()

    if action == "start":
        log.debug(f"Tunnel {domain} traffic through {destination}")
        _create_tunnel(domain, destination)
        if force:
            log.debug(f"Overriding {domain}'s default gateway")
            _configure_gateway(domain, gateway="", remove=True)
        _configure_gateway(domain, gateway=local_gateway)
        log.debug(f"Configure {domain} dns with {dns}")
        _configure_dns(domain, dns)
    elif action == "stop":
        log.debug(f"Stop the {domain} tunnel to {destination}")
        _delete_tunnel(domain, destination)
        _configure_gateway(domain, gateway=local_gateway, remove=True)
        _configure_dns(domain, remove=True)


@__main__.group()
def fw() -> None:
    """
    Manage firewall isolation of virtual machines.
    """
    pass


@fw.command()
@click.argument("src_domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("dst_domain", type=Type.domain, shell_complete=autocomplete("running"))
def allow(src_domain: Domain, dst_domain: Domain) -> None:
    """
    Allow communication between src_domain and dst_domain in both directions
    """

    err, _, _ = local_run(
        f"/usr/bin/sudo {NET_HELPER} firewall allow {src_domain} {src_domain.vnet()} {dst_domain} {dst_domain.vnet()}"
    )


@fw.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def reset(domain: Domain) -> None:
    """
    Reset the firewall of a domain
    """

    err, _, _ = local_run(
        f"/usr/bin/sudo {NET_HELPER} firewall reset {domain} {domain.vnet()}"
    )


@fw.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def destroy(domain: Domain) -> None:
    """
    Remove the firewall of a domain
    """

    err, _, _ = local_run(
        f"/usr/bin/sudo {NET_HELPER} firewall destroy {domain} {domain.vnet()}"
    )


@__main__.command()
@click.argument("id", type=int)
def cid(id: int):
    """
    Returns the domain name binding the provided CID.
    """
    for domain in get_running_domains():
        if domain.vsock() == id:
            print(domain.name)
