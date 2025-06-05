from libvirt import (  # type: ignore
    virStorageVol,
    libvirtError,
)
from xml.etree.ElementTree import (
    fromstring as xml_fromstring,
    tostring as xml_tostring,
)

from mofos.lib.common import libvirt_conn
from mofos.lib.utils import error
from mofos.lib.pool import pool

import logging

log = logging.getLogger(__name__)


class Volume:
    @classmethod
    def from_path(cls: type["Volume"], path: str) -> "Volume":
        for p in libvirt_conn().listAllStoragePools():
            for volume in p.listAllVolumes():
                if volume.path() == path:
                    return cls(volume)
        raise cls.NotFound(f"No volume associated to the path: {path}")

    @classmethod
    def from_name(cls, name: str) -> "Volume":
        return cls(pool().get_volume(name))

    def __init__(self, vol: virStorageVol) -> None:
        self.lv = vol
        self.name = vol.name()
        self.path = vol.path()

    def __str__(self) -> str:
        return self.name

    def remove(self) -> None:
        try:
            self.lv.delete()
        except libvirtError as e:
            error(f"Error while removing {self}: {e}")

    def clone(self, name: str) -> "Volume":
        xml = xml_fromstring(self.lv.XMLDesc())
        name_element = xml.findall("name")
        if name_element is None and len(name_element) != 1:
            raise Volume.CloneError(f"Couldn't clone {self}")

        name_element[0].text = name
        new_volume_xml = xml_tostring(xml, encoding="unicode")

        new_volume = pool().clone_volume(new_volume_xml, self.lv)
        if new_volume is None:
            raise Volume.CloneError(f"Couldn't clone {self}")

        return Volume(new_volume)

    def clone_as_backing(self, name: str) -> "Volume":
        xml = xml_fromstring(self.lv.XMLDesc())
        _capacity = xml.find("capacity")
        if _capacity is None or _capacity.text is None:
            raise Volume.CloneError("Could not retrieve the volume capacity")
        capacity = int(_capacity.text)

        new_xml = f"""
        <volume>
          <name>{name}</name>
          <capacity>{capacity}</capacity>
          <allocation>0</allocation>
          <target>
            <format type='qcow2'/>
          </target>
          <backingStore>
            <path>{self.path}</path>
            <format type='qcow2'/>
          </backingStore>
        </volume>"""

        new_volume = pool().new_volume(new_xml)
        if new_volume is None:
            raise Volume.CloneError(f"Could not clone {self} as backing file")

        return Volume(new_volume)

    class NotFound(Exception):
        pass

    class DeleteError(Exception):
        pass

    class CloneError(Exception):
        pass
