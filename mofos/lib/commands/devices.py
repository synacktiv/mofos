import click
import logging

from os import environ
from os.path import join

from mofos.lib.commands.main import __main__
from mofos.lib.kinds import Type, autocomplete, need_ssh_agent
from mofos.lib.domain import Domain
from mofos.lib.utils import error
from mofos.lib.logger import VmLogger
from mofos.lib.device import ls_usb, ls_pci

log: VmLogger = logging.getLogger(__name__)  # type: ignore


@__main__.group(invoke_without_command=True)
@click.pass_context
def usb(ctx):
    """
    List USB devices
    """
    if ctx.invoked_subcommand is None:
        ls_usb()


@usb.command("attach")
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("usb", type=click.STRING, shell_complete=autocomplete("usb"))
@click.option(
    "-f", "--force", is_flag=True, help="If already attached, detach and then re-attach"
)
@need_ssh_agent
def usb_attach(domain: Domain, usb: str, force: bool = False):
    """
    Attach a USB device to the given domain.
    """
    vendor_id, _, product_id = map(lambda x: x.lower(), usb.partition(":"))
    domain.attach_usb(vendor_id, product_id, force)


@usb.command("detach")
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("usb", type=click.STRING, shell_complete=autocomplete("usb"))
@click.option(
    "-f", "--force", is_flag=True, help="If already attached, detach and then re-attach"
)
@need_ssh_agent
def usb_detach(domain: Domain, usb: str, force: bool = False):
    """
    Detach a USB device to the given domain.
    """
    vendor_id, _, product_id = map(lambda x: x.lower(), usb.partition(":"))
    domain.detach_usb(vendor_id, product_id)


@__main__.group(invoke_without_command=True)
@click.pass_context
def pci(ctx):
    """
    List PCI devices
    """
    if ctx.invoked_subcommand is None:
        ls_pci()


@pci.command("attach")
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("pci", type=click.STRING, shell_complete=autocomplete("pci"))
@click.option(
    "-f", "--force", is_flag=True, help="If already attached, detach and then re-attach"
)
def pci_attach(domain: Domain, pci: str, force: bool = False) -> None:
    """
    Attach a PCI device to the given domain.
    """
    bus, slot_function = pci.split(":")
    slot, function = slot_function.split(".")
    dom = "00"
    domain.attach_pci(dom, bus, slot, function, force)


@pci.command("detach")
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("pci", type=click.STRING, shell_complete=autocomplete("pci"))
@click.option(
    "-f", "--force", is_flag=True, help="If already attached, detach and then re-attach"
)
def pci_detach(domain: Domain, pci: str, force: bool = False) -> None:
    """
    Detach a PCI device to the given domain.
    """
    bus, slot_function = pci.split(":")
    slot, function = slot_function.split(".")
    dom = "00"
    domain.detach_pci(dom, bus, slot, function)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("name", type=click.STRING)
@click.argument("size", type=click.STRING)
@click.option(
    "-d", "--destination", type=click.STRING, help="Mount point in the domain"
)
@need_ssh_agent
def add_disk(domain: Domain, name: str, size: str, destination: str = ""):
    """
    Create and attach a new disk.
    """
    if domain.shutoff():
        error("Cannot add disk to shutoff domains")

    domain.add_disk(name, size, destination)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("path", type=click.Path(exists=True, dir_okay=True))
@click.option("-d", "--destination", default="/mnt", help="Remote directory")
@click.option(
    "--no_mount", is_flag=True, help="Do not mount the directory in the domain"
)
@need_ssh_agent
def mount(domain: Domain, path: str, destination: str = "/mnt", no_mount: bool = False):
    """
    Mount a host folder inside the domain at the specified path.
    """
    if not path.startswith("/"):
        path = join(environ["PWD"], path)
    label = domain.mount(path, destination, not no_mount)
    if no_mount:
        log.info(f"Now mount {label} in {domain}")


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("path", type=click.Path(exists=True, dir_okay=True))
@click.option("-d", "--destination", default="/mnt", help="Remote directory")
@click.option(
    "--no_unmount",
    is_flag=True,
    help="Do not try to unmount the directory in the domain",
)
@need_ssh_agent
def umount(
    domain: Domain, path: str, destination: str = "/mnt", no_unmount: bool = False
):
    """
    Unmount a host folder inside the domain at the specified path.
    """
    if not path.startswith("/"):
        path = join(environ["PWD"], path)
    domain.umount(path, destination, not no_unmount)
