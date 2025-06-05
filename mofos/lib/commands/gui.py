import click
import logging

from os import environ
from re import search

from mofos.lib.utils import (
    error,
    local_exec,
    local_run,
    notify,
    wayland_active_window,
    x11_active_window,
    x11_window_info,
)
from mofos.lib.domain import Domain
from mofos.lib.commands.main import __main__
from mofos.lib.kinds import Type, autocomplete, need_ssh_agent
from mofos.lib.logger import VmLogger
from mofos.settings import config as cnf


log: VmLogger = logging.getLogger(__name__)  # type: ignore


def _domain_from_current_window_info() -> Domain:
    is_wayland = environ.get("WAYLAND_DISPLAY", False)
    if is_wayland:
        pid, wmclass = wayland_active_window()
        pass
    else:
        wid = x11_active_window()
        pid, wmclass, wmrole = x11_window_info(wid)

    # Use case of sensible-terminal adding x_{domain} in the class
    if wmclass.startswith("x_"):
        vmname = wmclass[2:]
        return Domain(vmname)

    # wmrole is only defined when
    elif not is_wayland and wmrole is not None and wmrole.startswith("x_"):
        vmname = wmrole[2:]
        return Domain(vmname)

    # If not, let's search in X11 variable for the associated PID and PPID
    process = []
    ppid = ""
    with open(f"/proc/{pid}/cmdline", "rb") as fp:
        process = fp.read().split(b"\x00")

    if environ.get("WAYLAND_DISPLAY", False):
        process_str = b" ".join(process).decode("utf8")
        # The command line is generated from XPRA_CMD
        re_ip = search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", process_str)
        if re_ip:
            return Domain.from_ip(re_ip.group(0))
        re_hostname = search(
            rf"ssh:{cnf.ssh.user}@([^:]+):{cnf.xpra.display}", process_str
        )
        if re_hostname:
            return Domain(re_hostname.group(1))

    else:
        # The parent process name contains the IP address of the domain
        # The PID process name is always `xpra_signal_listener`
        if len(process) > 1 and process[1] == b"/usr/bin/xpra_signal_listener":
            with open(f"/proc/{pid}/stat", "rb") as fp:
                ppid = fp.read().split(b"\x20")[3].decode("utf8")
            with open(f"/proc/{ppid}/cmdline", "rb") as fp:
                vmname = fp.read().decode("utf8")
                # The command line is generated from XPRA_CMD
                ip = search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", vmname)
                if ip is None:
                    raise Domain.NotFound("Could not find the focused domain")

                return Domain.from_ip(ip.group(0))

    # When it's not from a domain we want to know
    raise Domain.NotFound("Current window's domain not found")


class Clipboard:
    # for function variable
    def exec(command, input=b"", want_output=False):
        return local_run(command, input, want_output)

    def ssh_exec(self, command, input=b"", want_output=False):
        return self.domain.exec(command, cnf.ssh.user, input, want_output)

    def __init__(self, domain: Domain, display: str, direction: str):
        self.wayland = display.startswith("wayland")
        self.out = direction == "out"
        self.domain = domain

        if not self.out:
            self.left, self.right = Clipboard.exec, self.ssh_exec
            self.suffix = ">&- 2>&-"
            self.notif = "Push clipboard content to"
            if self.wayland:
                self.disp_r = cnf.xpra.display
            else:
                self.disp_l, self.disp_r = environ["DISPLAY"], cnf.xpra.display
        else:
            self.left, self.right = self.ssh_exec, Clipboard.exec
            self.suffix = ""
            self.notif = "Pull clipboard content from"
            if self.wayland:
                self.disp_l = cnf.xpra.display
            else:
                self.disp_l, self.disp_r = cnf.xpra.display, environ["DISPLAY"]

    def get_notif(self, domain) -> str:
        return f"{self.notif} {domain}"

    def get_clipboard(self):
        if self.wayland and not self.out:
            ret, out, _ = self.left("wl-paste -l", want_output=True)
            if ret:
                error("Error while using wl-paste", gui=True, title="Clipboard")
            if b"image/png" in out:
                self.format = "-t image/png"
                ret, out, err = self.left(f"wl-paste {self.format}", want_output=True)
                if ret:
                    error(
                        f"Only text or image/png formats are supported: {err.decode('utf8').strip()}",
                        gui=True,
                    )
            else:
                self.format = ""
                ret, out, _ = self.left(f"wl-paste {self.format}", want_output=True)
                if ret:
                    error("Error while using wl-paste", gui=True, title="Clipboard")
            return out
        else:
            cmd = f"xclip -d {self.disp_l} -sel clip -o"
            ret, out, _ = self.left(cmd, want_output=True)
            self.format = ""
            if ret:
                # Clipboard content is not a simple string
                # Retrieving formats
                cmd = f"xclip -d {self.disp_l} -sel clip -t TARGETS -o"
                ret, formats, err = self.left(cmd, want_output=True)
                log.debug(ret)
                log.debug(formats)
                if ret:
                    error(
                        f"Could not inspect clipboard content: {err.decode('utf8').strip()}",
                        gui=True,
                        title="Clipboard",
                    )
                # Prompting formats to user
                ret, format, _ = local_run(
                    cnf.tools.dmenu, input=formats, want_output=True
                )
                # dmenu returns a tuple of bytes
                if ret:
                    # The user probably cancelled the dmenu selector
                    raise SystemExit()

                self.format = "-t " + format[0].decode("utf8").strip()
                cmd = f"xclip -d {self.disp_l} -sel clip {self.format} -o"
                ret, out, _ = self.left(cmd, want_output=True)
                if ret:
                    error(
                        "Content too complex, do it manually",
                        gui=True,
                        title="Clipboard",
                    )
        return out

    def push_clipboard(self, buffer: str):
        if self.wayland and self.out:
            cmd = f"wl-copy {self.format}"
            # `want_output=False`, otherwise wl-copy hangs when retrieving the output
            ret, _, _ = self.right(cmd, input=buffer, want_output=False)
            err = b"Impossible to retrieve error output"
        else:
            cmd = f"xclip -d {self.disp_r} -sel clip -i {self.suffix}"
            ret, _, err = self.right(cmd, input=buffer, want_output=True)

        if ret:
            str_err = err.decode("utf8").strip()
            raise Clipboard.ClipboardError(
                f"Error while pushing to the clipboard: {str_err}"
            )

    class ClipboardError(Exception):
        pass


@__main__.command()
@click.argument("direction", type=click.Choice(["in", "out"]))
@click.argument(
    "domain", type=Type.domain, shell_complete=autocomplete("running"), required=False
)
@need_ssh_agent
def clipboard(direction: str, domain: Domain):
    """
    Pull/push the clipboard of/on a given domain.
    """
    if domain is None:
        # If window belongs to host, domain => ""
        try:
            domain = _domain_from_current_window_info()
        except Exception as e:
            raise e
            log.exception(e)
            raise SystemExit(1)

    clip = Clipboard(domain, environ.get("WAYLAND_DISPLAY", "Xorg"), direction)
    buffer = clip.get_clipboard()
    clip.push_clipboard(buffer)
    notify("Low", f"Clipboard: {clip.get_notif(domain)}")


@__main__.command()
def focus():
    """
    Print the current focus domain
    """
    try:
        domain = _domain_from_current_window_info()
    except Domain.NotFound as e:
        log.exception(e)
        raise SystemExit(1)
    print(domain.name)


@__main__.command()
@click.argument("command", type=click.STRING)
@need_ssh_agent
def sensible_exec(command):
    """
    Execute a program according to the current focus window.
    """
    try:
        domain = _domain_from_current_window_info()
    except Domain.NotFound as e:
        log.exception(e)
        raise SystemExit()
    local_exec(command.replace("DOMAIN", domain.name))
