from os import listdir
from os.path import join, isdir, exists
from typing import Any

from mofos.lib.domain import get_all_domains


def ls_usb() -> None:
    devices = UsbDevice.ls()
    rows = []
    for dev in sorted(devices, key=lambda x: x.identifier):
        domains = ", ".join(
            dom.name
            for dom in get_all_domains()
            if dom.has_device("usb", (dev.tuple()))
        )
        rows.append([dev, dev.title(), domains])
    try:
        from prettytable import PrettyTable

        pt = PrettyTable()
        pt.field_names = ["ID", "Device", "Attached to"]
        pt.add_rows(rows)
        pt.align = "l"
        print(pt)
    except ImportError:
        for row in rows:
            print(row)


def ls_pci() -> None:
    devices = PciDevice.ls()
    rows = []
    for dev in sorted(devices, key=lambda x: x.identifier):
        domains = ", ".join(
            dom.name
            for dom in get_all_domains()
            if dom.has_device("pci", (dev.tuple()))
        )
        rows.append([f"{dev}", dev.title(), domains])
    try:
        from prettytable import PrettyTable

        pt = PrettyTable()
        pt.field_names = ["ID", "Device", "Attached to"]
        pt.add_rows(rows)
        pt.align = "l"
        print(pt)
    except ImportError:
        for row in rows:
            print(row)


def _read_file_content(file_path: str) -> str:
    try:
        with open(file_path, "r") as file:
            return file.read().strip()
    except (FileNotFoundError, IOError):
        return ""


class Device:
    ID_PATH: list[str] = []
    DEVICES_PATH = ""

    identifier: str
    description: str
    id: str
    short_identifier: str
    klass: str
    vendor_id: str
    vendor_desc: str
    vendor: str

    @staticmethod
    def _search_in_db(type: str, devices: list["Device"]) -> None:
        for db in listdir("/lib/udev/hwdb.d/"):
            with open(f"/lib/udev/hwdb.d/{db}", "r") as fp:
                for line in fp:
                    if line.startswith(type):
                        for device in devices:
                            if device.match(line.strip()):
                                _, _, desc = next(fp).strip().partition("=")
                                device.description = desc

    @staticmethod
    def search_in_db(devices: list["Device"]) -> None:
        raise NotImplementedError

    @classmethod
    def ls(cls) -> list["Device"]:
        devices = cls.get_devices()
        cls.search_in_db(devices)
        return devices

    @classmethod
    def get_devices(cls) -> list["Device"]:
        result = []
        devices_path = cls.DEVICES_PATH
        if not exists(devices_path):
            return []

        for device in listdir(devices_path):
            device_path = join(devices_path, device)

            if not isdir(device_path):
                continue

            # Read IDs
            ids = []
            for id in cls.ID_PATH:
                dev = _read_file_content(join(device_path, id))
                if dev:
                    ids.append(dev)

            # No vendor id
            if not ids:
                continue
            result.append(cls(device, tuple(ids)))
        return result

    def __init__(self, identifier, tup: tuple[str, ...]) -> None:
        raise NotImplementedError

    def match(self, db_line) -> bool:
        return db_line == self.identifier

    def title(self) -> str:
        raise NotImplementedError

    def tuple(self) -> tuple[Any, ...]:
        raise NotImplementedError

    def __str__(self) -> str:
        raise NotImplementedError

    class LocalInformationError(Exception):
        pass

    class InvalidIdentifier(Exception):
        pass


class UsbDevice(Device):
    @staticmethod
    def search_in_db(devices: list[Device]) -> None:
        with open("/usr/share/misc/usb.ids") as fp:
            for line in fp:
                if line.startswith("\t"):
                    continue
                elif line.startswith("# List of known device classes"):
                    break
                else:
                    for device in devices:
                        if line.startswith(device.vendor_id):
                            _, _, device.vendor_desc = line.strip().partition("  ")

        super(UsbDevice, UsbDevice)._search_in_db("usb", devices)

    ID_PATH = ["idVendor", "idProduct", "manufacturer", "product"]
    DEVICES_PATH = "/sys/bus/usb/devices"

    vendor_id: str
    product_id: str
    manufacturer: str
    product: str

    def __init__(self, _, tup: tuple[str, ...]) -> None:
        if len(tup) == 3:
            self.vendor_id, self.product_id, self.manufacturer = tup
            self.product = ""
        elif len(tup) == 4:
            self.vendor_id, self.product_id, self.manufacturer, self.product = tup
        else:
            raise Device.InvalidIdentifier()
        self.id = self.product_id

        self.identifier = f"usb:v{self.vendor_id.upper()}p{self.product_id.upper()}*"
        self.description = ""
        self.vendor_desc = ""
        self.id = f"{self.vendor_id}:{self.product_id}"

    def title(self) -> str:
        desc = self.description if self.description else self.product
        vendor_desc = self.vendor_desc if self.vendor_desc else self.manufacturer
        return f"{vendor_desc}, {desc}"

    def tuple(self) -> tuple[Any, ...]:
        return (self.vendor_id, self.product_id)

    def __str__(self) -> str:
        return f"{self.vendor_id}:{self.product_id}"


class PciDevice(Device):
    @staticmethod
    def search_in_db(devices: list[Device]) -> None:
        # vendor description
        with open("/usr/share/misc/pci.ids") as fp:
            for line in fp:
                if line.startswith("\t"):
                    continue
                elif line.startswith("# List of known device classes"):
                    break
                else:
                    for device in devices:
                        if line.startswith(device.vendor):
                            _, _, device.vendor_desc = line.strip().partition("  ")

            # classes
            classes = {}
            current_class = None
            current_subclass = None
            for line in fp:
                line = line.rstrip()
                if line.startswith("C "):
                    parts = line.split(maxsplit=2)
                    class_code = parts[1]
                    class_description = parts[2]
                    classes[class_code] = class_description.strip()
                    current_class = class_code
                    current_subclass = None
                elif line.startswith("\t") and current_class:
                    tab = line[1]
                    line = line.strip()
                    code, _, description = line.partition(" ")
                    if tab == "\t":
                        continue
                        classes[
                            f"{current_class}{current_subclass}{code}"
                        ] = description.strip()
                    else:
                        classes[f"{current_class}{code}"] = description.strip()
                        current_subclass = code

            for device in devices:
                device.klass = classes[device.klass]

        # description
        super(PciDevice, PciDevice)._search_in_db("pci", devices)

    ID_PATH = ["vendor", "device", "subsystem_vendor", "subsystem_device", "class"]
    DEVICES_PATH = "/sys/bus/pci/devices"

    device: str
    subsystem_vendor: str
    subsystem_device: str
    short_id: str
    long_id: str
    domain: str
    bus: str
    slot: str
    function: str

    def __init__(self, identifier, tup: tuple[str, ...]) -> None:
        self.identifier = identifier
        _, _, self.short_identifier = identifier.partition(":")
        self.domain, self.bus, slot_function = identifier.split(":")
        self.slot, self.function = slot_function.split(".")
        (
            self.vendor,
            self.device,
            self.subsystem_vendor,
            self.subsystem_device,
            self.klass,
        ) = map(lambda x: x[2:], tup)
        self.klass = self.klass[:4]
        self.short_id = f"pci:v0000{self.vendor.upper()}d0000{self.device.upper()}"
        self.long_id = (
            f"{self.short_id}sv0000{self.subsystem_vendor.upper()}"
            f"sd0000{self.subsystem_device.upper()}*"
        )
        self.short_id += "*"
        self.description = ""

    def title(self) -> str:
        if not self.description:
            self.description = f"Device {self.device}"
        return f"{self.klass}: {self.vendor_desc} {self.description}"

    def tuple(self) -> tuple[Any, ...]:
        return (self.domain, self.bus, self.slot, self.function)

    def match(self, db_line) -> bool:
        return db_line in [self.short_id, self.long_id]

    def __str__(self) -> str:
        return self.short_identifier
