from libvirt import open as libvirt_open, libvirtError  # type: ignore
from functools import cache

from mofos.lib.utils import error
from mofos.settings import config as cnf


@cache
def libvirt_conn():
    try:
        return libvirt_open(cnf.libvirt.qemu)
    except libvirtError as e:
        error(repr(e))
