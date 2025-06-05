from os import environ
from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack

SSH2_AGENTC_REQUEST_IDENTITIES = b"\x0b"


def is_ssh_agent_locked() -> bool:
    sshagent_path = environ.get("SSH_AUTH_SOCK", "")
    if not sshagent_path:
        return False

    agent = socket(AF_UNIX, SOCK_STREAM)
    agent.connect(sshagent_path)
    msg = SSH2_AGENTC_REQUEST_IDENTITIES
    agent.send(pack(">I", len(msg)) + msg)
    data = agent.recv(4)
    return unpack(">I", data)[0] != 5
