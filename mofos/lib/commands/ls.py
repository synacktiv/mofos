import click

from json import loads
from colorama import Fore, Style

from mofos.lib.commands.main import __main__
from mofos.lib.device import ls_pci, ls_usb
from mofos.lib.utils import (
    error,
    local_run,
    local_exec,
)
from mofos.lib.domain import (
    Domain,
    get_all_domains,
)
from mofos.settings import NET_HELPER


@__main__.group(invoke_without_command=True)
@click.pass_context
def ls(ctx):
    """
    List domains and their states.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(domains)


@ls.command()
@click.pass_context
def all(ctx):
    ctx.invoke(domains, only_managed=False)


@ls.command()
def domains(only_managed: bool = True):
    try:
        from prettytable import PrettyTable

        pt = PrettyTable()
        pt.field_names = [
            "Id",
            "Name",
            "State",
            "Description",
            "Alias",
            "Cid",
            "IPv4 address",
        ]
        domains = get_all_domains()
        for domain in sorted(domains, key=lambda x: (x.state(), x.id, x.name)):
            domain.load_metadata()
            domain.vsock()
            if not only_managed or domain.managed:
                pt.add_row(
                    [
                        str(domain.id) if domain.id > 0 else "",
                        domain.name,
                        # Colorize in green if state == running else red
                        f"{Fore.GREEN}running{Fore.RESET}"
                        if domain.state() == "running"
                        else f"{Fore.RED}{domain.state()}{Fore.RESET}",
                        domain.description,
                        domain.alias,
                        domain.vsock() if domain.vsock() else "",
                        domain.ip if domain.ip else "",
                    ]
                )
        pt.align = "l"
        print(pt)
    except ImportError:
        local_exec("/usr/bin/virsh list --all")


@ls.command()
def usb():
    """
    List USB devices.
    """
    ls_usb()


@ls.command()
def pci():
    """
    List PCI devices.
    """
    ls_pci()


@ls.command()
def tun():
    """
    List tunnels information.
    """
    ls_tun()


# To allow `mofos tun` shortcut instead of `mofos ls tun`
@__main__.command("tun")
def tun2():
    """
    List tunnels information
    """
    ls_tun()


def ls_tun():
    ret, out, err = local_run(f"{NET_HELPER} list", want_output=True)
    if ret:
        error(f"Calling {NET_HELPER} list -> {err}")
    net = loads(out)
    tun = {}

    def color(state) -> str:
        match state:
            case "UP":
                return f"{Fore.GREEN}{state}{Style.RESET_ALL}"
            case _:
                return f"{Fore.RED}{state}{Style.RESET_ALL}"

    for rule in net["rules"]:
        try:
            ip = rule["src"]
            domain = Domain.from_ip(ip)
            route = [route for route in net["routes"] if route["id"] == rule["table"]]
            route = route[0]
            dev = [dev for dev in net["devices"] if dev["name"] == route["dev"]]
            dev = dev[0]
            tun[domain.name] = {
                "dom": domain,
                "dest": route["dest"],
                "state": dev["state"],
            }
        except (Domain.NotFound, IndexError):
            continue
    try:
        from prettytable import PrettyTable

        pt = PrettyTable()
        pt.field_names = ["Id", "Name", "Gateway", "State"]
        for domain in sorted(
            get_all_domains(), key=lambda x: (x.state(), x.id, x.name)
        ):
            if domain.name in tun.keys():
                t = tun[domain.name]
                pt.add_row([t["dom"].id, t["dom"].name, t["dest"], color(t["state"])])
        pt.align = "l"
        print(pt)

    except ImportError:
        for t in tun.items():
            print(f"{t['dom']} -> {t['dest']}: {t['state']}")


@ls.command()
def mnt():
    info = {}
    for dom in get_all_domains():
        mnt = list(dom.get_mnt())
        if mnt:
            info[dom] = list(map(list, zip(*mnt)))
    try:
        from prettytable import PrettyTable

        pt = PrettyTable()
        pt.field_names = ["Id", "Name", "Local directory", "Label"]
        for domain, mnt in info.items():
            pt.add_row(
                [
                    str(domain.id) if domain.id > 0 else "",
                    domain.name,
                    "\n".join(mnt[0]),
                    "\n".join(mnt[1]),
                ]
            )
        pt.align = "l"
        print(pt)
    except ImportError:
        for domain, mnt in info.items():
            print(f"{domain.id}: {domain.name}, {mnt[0]} @ {mnt[1]}")
