#!/usr/bin/env python3

from socket import AF_VSOCK, SOL_SOCKET, SO_REUSEADDR, SHUT_WR
from socketserver import TCPServer, BaseRequestHandler, ThreadingMixIn
from os import listdir
from re import search
from subprocess import run

CID = 2  # Host
PORT = 65001  # Arbitrary port


def prompt_for_confirmation(cid: str) -> bool:
    return not run(
        [
            "/usr/bin/zenity",
            "--title",
            f"sudo authentication for {cid}",
            "--question",
            "--text",
            (f"Allow privilege elevation on {cid}?"),
        ]
    ).returncode


def resolve_cid(id: int) -> str:
    regex = r"-name.guest=([^,]+).*guest-cid\":(\d+),"
    try:
        for pid in listdir("/proc"):
            if pid.isdigit():
                with open(f"/proc/{pid}/cmdline") as fp:
                    cmdline = fp.read()
                    if cmdline.startswith("/usr/bin/qemu-system-"):
                        match = search(regex, cmdline)
                        if match and id == int(match.group(2)):
                            return match.group(1)
    except Exception:
        pass
    return ""


class Handler(BaseRequestHandler):
    def handle(self) -> None:
        cid, _ = self.client_address
        cid = resolve_cid(cid)
        ret = prompt_for_confirmation(cid)
        if ret:
            self.request.sendall(b"1\n")
        else:
            self.request.sendall(b"0\n")
        self.request.shutdown(SHUT_WR)
        # To let time for the peer to properly shutdown
        self.request.recv(1)


class ThreadedVsockServer(ThreadingMixIn, TCPServer):
    address_family = AF_VSOCK


if __name__ == "__main__":
    try:
        with ThreadedVsockServer((CID, PORT), Handler) as server:  # type: ignore
            server.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server.serve_forever()
    except KeyboardInterrupt:
        raise SystemExit()
