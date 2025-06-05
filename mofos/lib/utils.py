from shlex import split as shlex_split
from os import execve, environ, remove, makedirs
from os.path import exists
from subprocess import run
from json import loads
from re import search
from random import randbytes
from typing import Union

from mofos.settings import PROJECT
from mofos.lib.logger import VmLogger

import logging

log: VmLogger = logging.getLogger(__name__)  # type: ignore


def error(msg: str, gui: bool = False, title: str = "", severity: str = "Low") -> None:
    if gui:
        header = title if title else "Misc"
        notify(header, severity, msg)
    log.error(msg)
    raise SystemExit(1)


def notify(urgency: str, msg: str, title: str = PROJECT) -> None:
    if exists("/usr/bin/notify-send"):
        local_run(f'/usr/bin/notify-send {title} -u {urgency} "{msg}"')


def local_exec(cmd: Union[str, list[str]]) -> None:
    if isinstance(cmd, str):
        command = shlex_split(cmd)
    else:
        command = cmd
    log.debug(f"Executing: {''.join(command)}")
    execve(command[0], command, environ)


def local_run(
    cmd: Union[str, list[str]],
    input: bytes = b"",
    want_output: bool = False,
    daemon: bool = False,
) -> tuple[int, bytes, bytes]:
    """
    If cmd is a list, then it is assumed that the caller already cleaned the command.
    """
    if isinstance(cmd, str):
        cmd = shlex_split(cmd)
    log.debug(" ".join(cmd))
    if want_output:
        proc = run(cmd, input=input, capture_output=want_output)
        return proc.returncode, proc.stdout, proc.stderr
    else:
        if log.isEnabledFor(logging.DEBUG):
            proc = run(
                cmd,
                input=None if not input else input,
                capture_output=False,
                start_new_session=daemon,
            )
            return proc.returncode, b"", b""

        else:
            with open("/dev/null", "wb") as devnull:
                proc = run(
                    cmd,
                    input=None if not input else input,
                    capture_output=False,
                    stdout=devnull,
                    stderr=devnull,
                    start_new_session=daemon,
                )
                return proc.returncode, b"", b""


def x11_active_window() -> str:
    cmd = "/usr/bin/xprop -root _NET_ACTIVE_WINDOW"
    ret, out, _ = local_run(cmd, want_output=True)
    if ret:
        error("Can't find the root window")
    wid = search(b"# (0x[a-f0-9]+)\\n$", out)
    if wid:
        return wid.group(1).decode("utf8")
    else:
        return ""


def x11_window_info(wid: str) -> tuple[str, str, str]:
    cmd = f"/usr/bin/xprop -id {wid} _NET_WM_PID WM_CLASS WM_WINDOW_ROLE"
    ret, out, _ = local_run(cmd, want_output=True)
    if ret:
        error("Can't find the root window")
    lines = out.split(b"\n")
    _pid = search(b"= ([0-9]+)$", lines[0])
    if _pid is None:
        return ("", "", "")
    pid = _pid.group(1).decode("utf8")
    _wmclass = search(b'= "([^"]+)",', lines[1])
    if _wmclass is None:
        return (pid, "", "")
    wmclass = _wmclass.group(1).decode("utf8")

    _wmrole = search(b'= "([^"]+)"', lines[2])
    if _wmrole is None:
        return (pid, wmclass, "")
    wmrole = _wmrole.group(1).decode("utf8")
    return pid, wmclass, wmrole


def wayland_active_window() -> tuple[str, str]:
    def browse_sway_tree(root):
        if root["focused"]:
            return root
        for node in root["nodes"]:
            res = browse_sway_tree(node)
            if res:
                return res
        return ()

    if environ.get("SWAYSOCK", False):
        ret, out, _ = local_run("swaymsg -t get_tree", want_output=True)
        if ret:
            error("Can't retrieve the tree windows")
        tree = loads(out)
        for node in tree["nodes"]:
            res = browse_sway_tree(node)
            if res:
                return res["pid"], res["app_id"]
        return "", ""

    raise NotImplementedError


def configure_ssh_known_hosts(known_hosts_file: str, host_key: str, label: str) -> None:
    makedirs(f"{environ['HOME']}/.ssh", exist_ok=True)
    local_run(f"/usr/bin/ssh-keygen -f {known_hosts_file} -R {label}")
    with open(known_hosts_file, "a") as fp:
        fp.write(f"{label} {host_key}")
    local_run(f"/usr/bin/ssh-keygen -Hf {known_hosts_file}")
    remove(f"{known_hosts_file}.old")


def randomize_hostname():
    return "DESKTOP-" + randbytes(4).hex()[:-1].upper()
