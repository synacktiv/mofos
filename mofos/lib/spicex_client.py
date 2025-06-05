from os import environ
from os.path import exists
from socket import socket, AF_UNIX, SOCK_STREAM
from time import sleep

from mofos.lib.utils import error, local_run


class _UsbDevice:
    def __init__(self, line: str):
        cols = line.strip().split("|")
        self.id = cols[0]
        self.manufacturer = cols[1]
        self.product = cols[2]
        self.descriptor = cols[3]
        self.bus = int(cols[4])
        self.address = int(cols[5])
        self.can_redirect = True if int(cols[6]) == 1 else False

    @staticmethod
    def display(devices):
        try:
            from prettytable import PrettyTable

            pt = PrettyTable()
            pt.field_names = [
                "Id",
                "Manufacturer",
                "Product",
                "Descriptor",
                "Can redirect",
            ]
            for device in devices:
                pt.add_row(
                    [
                        device.id,
                        device.manufacturer,
                        device.product,
                        device.descriptor,
                        "Yes" if device.can_redirect else "No",
                    ]
                )
            pt.align = "l"
            print(pt)

        except ImportError:
            for device in devices:
                print(
                    (
                        f"#{device.id}: {device.manufacturer}, "
                        f"{device.product} {device.descriptor} "
                        f"-> can redirect: {device.can_redirect}"
                    )
                )


class SpiceXSession:
    class AlreadyAttached(Exception):
        pass

    class FailedOperation(Exception):
        pass

    class InvalidMessageFormat(Exception):
        pass

    class MissingIndex(Exception):
        pass

    class NotAttached(Exception):
        pass

    @staticmethod
    def _readall(sock: socket):
        buf_len = 1024
        data = b""
        while True:
            chunk = sock.recv(buf_len)
            if not chunk:
                break
            data += chunk
        if data == b"Invalid message format":
            raise SpiceXSession.InvalidMessageFormat(data.decode("utf8"))
        elif b"already attached" in data:
            raise SpiceXSession.AlreadyAttached(data.decode("utf8"))
        elif b"not attached" in data:
            raise SpiceXSession.NotAttached(data.decode("utf8"))
        return data

    def __init__(self, domain: str, port: int):
        self.domain = domain
        self.port = port
        self.unix_socket_path = f"{environ['XDG_RUNTIME_DIR']}/spicex-{self.port}.sock"

    def start(self):
        if not self.started():
            err, _, _ = local_run(f"/bin/systemctl --user start spicex@{self.port}")
            if err:
                error(
                    (
                        f"Could not stop the spiceX server for port: {self.port} "
                        f"of domain: {self.domain}"
                    )
                )

    def stop(self):
        if self.started():
            err, _, _ = local_run(f"/bin/systemctl --user stop spicex@{self.port}")
            if err:
                error(
                    (
                        f"Could not stop the spiceX server for port: {self.port} "
                        f"of domain: {self.domain}"
                    )
                )

    def started(self) -> bool:
        return exists(self.unix_socket_path)

    def do_action(self, action: str, index=0):
        """
        Start a systemd unit if not already started, then interact with the socket
        to run command and get result from the spiceX daemon.
        """

        # Waiting for the service to create the unix socket
        while not exists(self.unix_socket_path):
            sleep(0.1)
        sock = socket(AF_UNIX, SOCK_STREAM)
        sock.connect(self.unix_socket_path)
        try:
            if action == "list":
                sock.sendall(b"list:")
                answer = SpiceXSession._readall(sock).decode("utf8").strip()

                devices = []
                for line in answer.split("\n"):
                    devices.append(_UsbDevice(line))

                _UsbDevice.display(devices)
                return True

            elif action == "attach" or action == "detach":
                if index < 1:
                    raise SpiceXSession.MissingIndex(f"index < 1: {index}")

                sock.sendall(f"{action}:{index}".encode("utf8"))
                result = SpiceXSession._readall(sock).rstrip(b"\x00").decode("utf8")
                if result != "success":
                    raise SpiceXSession.FailedOperation()

            else:
                raise NotImplementedError()

        except SpiceXSession.InvalidMessageFormat as e:
            raise SpiceXSession.InvalidMessageFormat(f"{e}, with action: {action}")
