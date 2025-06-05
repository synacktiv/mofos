import click

from json import load
from typing import Callable
from functools import wraps

from mofos.lib.domain import (
    Domain,
    get_all_vms,
    get_running_vms,
    get_template_domains,
    get_shutoff_vms,
)
from mofos.lib.utils import notify
from mofos.lib.sshagent import is_ssh_agent_locked
from mofos.lib.device import UsbDevice, PciDevice
from mofos.settings import config as cnf, LIBVIRT_OS_VARIANTS


def _get_boxes():
    try:
        if cnf.pivot.box.file:
            with open(cnf.pivot.box.file, "r") as fp:
                data = load(fp)
                if cnf.pivot.box.suffix:
                    return [f"{elem['alias']}{cnf.pivot.box.suffix}" for elem in data]
                else:
                    return [f"{elem['alias']}" for elem in data]
    except Exception:
        return []


class VmDomain(click.ParamType):
    name = "Domain"

    def convert(self, value, param, ctx):
        if isinstance(value, str):
            return Domain(value)
        self.fail(f"{value} is not a valid domain")


class Type:
    domain = VmDomain()


def autocomplete(selector: str) -> Callable:
    lookup: dict[str, Callable] = {
        "all": lambda: get_all_vms(),
        "running": lambda: get_running_vms(),
        "template": lambda: [x.name for x in get_template_domains()],
        "stopped": lambda: get_shutoff_vms(),
        "variant": lambda: list(LIBVIRT_OS_VARIANTS.keys()),
        "boxes": lambda: _get_boxes(),
        "usb": lambda: list(map(lambda x: x.id, UsbDevice.get_devices())),
        "pci": lambda: list(map(lambda x: x.short_identifier, PciDevice.get_devices())),
    }
    return lambda _, __, ___: lookup.get(selector, lambda: [])()


def need_ssh_agent(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not is_ssh_agent_locked():
            notify("Low", "SSH-AGENT locked")
        return func(*args, **kwargs)

    return wrapper
