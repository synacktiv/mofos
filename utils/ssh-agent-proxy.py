#!/usr/bin/env python3

from socket import socket, AF_UNIX, AF_VSOCK, SOCK_STREAM
from socketserver import TCPServer, BaseRequestHandler, ThreadingMixIn
from os import environ, listdir
from re import search
from select import select
from struct import unpack, pack
from subprocess import run
from base64 import b64encode
from hashlib import sha256

CID = 2  # Host
PORT = 65000  # Arbitrary ports
BUF_SIZE = 4096
OKAY = ["externalkey"]
CACHE_DURATION = 3600


SSH_AGENT_SUCCESS = 6
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_EXTENSION = 27

SSH_AGENT_REQUESTS = [
    SSH_AGENT_SUCCESS,
    SSH2_AGENTC_REQUEST_IDENTITIES,
    SSH2_AGENT_IDENTITIES_ANSWER,
    SSH2_AGENTC_SIGN_REQUEST,
    SSH2_AGENT_SIGN_RESPONSE,
    SSH_AGENTC_EXTENSION,
]


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


class SshKey:
    KEYTYPES = {7: "ssh-rsa", 11: "ssh-ed25519"}

    type_code: int
    type: str
    pub: bytes
    comment: str

    def __init__(self, type_code: int, pub: bytes, comment: str = "") -> None:
        self.type_code = type_code
        self.type = self.KEYTYPES[type_code]
        self.pub = pub
        self.comment = comment

    def to_bytes(self) -> bytes:
        size = 4 + len(self.type.encode("utf8")) + len(self.pub)
        return (
            pack(">I", size)
            + pack(">I", self.type_code)
            + self.type.encode("utf8")
            + self.pub
            + pack(">I", len(self.comment))
            + self.comment.encode("utf8")
        )

    def to_str(self) -> str:
        return f"{self.comment} {b64encode(self.pub).decode('utf8')}"

    def fingerprint(self) -> str:
        return b64encode(
            sha256(
                pack(">I", self.type_code) + self.type.encode("utf8") + self.pub
            ).digest()
        ).decode("utf8")


def prompt_for_confirmation(cid: str, key: SshKey) -> bool:
    return not run(
        [
            "/usr/bin/zenity",
            "--title",
            f"ssh-askpass for {cid}",
            "--question",
            "--text",
            (
                f"Allow use of {key.comment} "
                f"by {cid}?\nKey fingerprint: "
                f"{key.fingerprint()}."
            ),
        ]
    ).returncode


def readint(data: bytes, offset: int = 0) -> int:
    return unpack(">I", data[offset : offset + 4])[0]


def readbytes(data: bytes, offset: int = 0, size: int = 0) -> bytes:
    return data[offset : offset + size]


def readbyte(data: bytes, offset: int = 0) -> int:
    return data[offset]


def readkey(blob: bytes, offset: int, has_comment: bool = False) -> tuple[int, SshKey]:
    size = readint(blob, offset)
    offset += 4

    type_int = readint(blob, offset)
    type_str = SshKey.KEYTYPES[type_int]
    type_len = len(type_str)
    pub = readbytes(blob, offset + 4 + type_len, size - 4 - type_len)

    sshkey = SshKey(type_int, pub)
    offset += size

    if has_comment:
        comment_size = readint(blob, offset)
        comment = readbytes(blob, offset + 4, comment_size)
        sshkey.comment = comment.decode("utf8")
        offset += 4 + comment_size

    return offset, sshkey


def recvall(sock) -> bytes:
    data = b""
    while True:
        part = sock.recv(BUF_SIZE)
        data += part
        if len(part) < BUF_SIZE:
            break
    return data


class Handler(BaseRequestHandler):
    def handle(self) -> None:
        cid, _ = self.client_address
        cid = resolve_cid(cid)
        ssh_agent_sock_path = environ["SSH_AUTH_SOCK"]
        with socket(AF_UNIX, SOCK_STREAM) as ssh_agent_sock:
            print(f"Connection from {cid} to {ssh_agent_sock_path}")
            ssh_agent_sock.connect(ssh_agent_sock_path)

            allowed_keys: list[SshKey] = []
            while True:
                readable, _, _ = select([self.request, ssh_agent_sock], [], [])
                if readable[0] == self.request:
                    out = ssh_agent_sock
                elif readable[0] == ssh_agent_sock:
                    out = self.request
                else:
                    return

                data = recvall(readable[0])

                if len(data) == 0:
                    return

                msg_size = readint(data)
                if msg_size != len(data) - 4:
                    raise SystemError("Abort")

                msg_type = readbyte(data, 4)
                # CLIENT
                if msg_type not in SSH_AGENT_REQUESTS:
                    out = self.request
                    data = b"\x00\x00\x00\x01\x05"
                elif msg_type == SSH2_AGENTC_SIGN_REQUEST:
                    offset = 5
                    # Read only the first part of the message
                    _, sshkey = readkey(data, offset)
                    for key in allowed_keys:
                        if key.pub == sshkey.pub and prompt_for_confirmation(cid, key):
                            break
                    else:
                        out = self.request
                        data = b"\x00\x00\x00\x01\x05"

                # SERVER
                elif msg_type == SSH2_AGENT_IDENTITIES_ANSWER:
                    # Read all the keys in the message
                    n_entries = readint(data, 5)
                    offset = 9
                    new_keys = []
                    for k in range(n_entries):
                        offset, sshkey = readkey(data, offset, has_comment=True)
                        # If the key is whitelisted
                        if sshkey.comment in OKAY:
                            new_keys.append(sshkey)

                    # Modify the response with only the authorized keys
                    new_data = b""
                    n_entries = 0
                    for key in new_keys:
                        n_entries += 1
                        new_data += key.to_bytes()

                    new_data = (
                        pack("B", SSH2_AGENT_IDENTITIES_ANSWER)
                        + pack(">I", n_entries)
                        + new_data
                    )
                    final_len = pack(">I", len(new_data))
                    data = final_len + new_data
                    # Save the authorized keys for signing requests
                    allowed_keys = new_keys
                else:
                    # SSH_AGENT_SUCCESS
                    # SSH2_AGENT_SIGN_RESPONSE
                    # SSH_AGENTC_EXTENSION
                    # SSH2_AGENTC_REQUEST_IDENTITIES
                    pass

                out.send(data)


class ThreadedVsockServer(ThreadingMixIn, TCPServer):
    address_family = AF_VSOCK


if __name__ == "__main__":
    try:
        with ThreadedVsockServer((CID, PORT), Handler) as server:  # type: ignore
            server.serve_forever()
    except KeyboardInterrupt:
        raise SystemExit()
