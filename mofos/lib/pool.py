from libvirt import virStorageVol  # type: ignore
from lxml import etree  # type: ignore
from functools import cache
from typing import Optional

from mofos.lib.common import libvirt_conn
from mofos.settings import config


@cache
def pool() -> "Pool":
    return Pool(config.libvirt.pool)


class Pool:
    def __init__(self, name: str) -> None:
        self.lv = libvirt_conn().storagePoolLookupByName(name)
        self.name = name

    def clone_volume(self, xml: str, volume: virStorageVol) -> virStorageVol:
        return self.lv.createXMLFrom(xml, volume)

    def new_volume(self, xml: str) -> virStorageVol:
        return self.lv.createXML(xml)

    def get_volume(self, name: str) -> virStorageVol:
        return self.lv.storageVolLookupByName(name)

    def path(self) -> Optional[str]:
        root = etree.fromstring(self.lv.XMLDesc())
        m = root.xpath("/pool/target/path")
        if m:
            return m[0]
        return None
