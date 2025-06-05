import click
import logging

from os import fork, setsid, environ, mkdir, remove
from os.path import exists, join
from sys import stdout
from time import sleep
from json import dump
from typing import Any
from itertools import chain

from mofos.lib.commands.main import __main__
from mofos.lib.kinds import Type, autocomplete, need_ssh_agent
from mofos.lib.domain import (
    Domain,
    get_all_domains,
    get_running_domains,
    get_template_domains,
    get_template_sshpubkey,
)
from mofos.lib.utils import (
    local_exec,
    error,
    local_run,
    configure_ssh_known_hosts,
    randomize_hostname,
)
from mofos.lib.logger import VmLogger
from mofos.settings import config as cnf, HOME

log: VmLogger = logging.getLogger(__name__)  # type: ignore


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("stopped"))
@click.option("-w", "--wait", is_flag=True, help="Wait for the domain to boot.")
@click.option(
    "-r", "--raw", is_flag=True, help="Does not check whether the SSH service is up"
)
def start(domain: Domain, wait: bool, raw: bool):
    """
    Start the domain.
    """
    timeout = 60
    domain.start()

    if wait:
        domain.wait(timeout)
        domain.poststart()
    elif not raw:
        # double fork
        if fork() == 0:
            setsid()
            if fork() == 0:
                domain.wait(timeout)
                domain.poststart()
                raise SystemExit()
            else:
                sleep(timeout)
                raise SystemExit()


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def stop(domain: Domain):
    """
    Stop the domain.
    """
    domain.stop()


@__main__.command()
def stop_all():
    """
    Stop all running domains.
    """
    for domain in get_running_domains():
        domain.stop()


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def kill(domain: Domain):
    """
    Stop the domain.

    Arguments:
        #domain:string:running
            Target domain
    """
    if domain.running():
        domain.kill()
    else:
        error(f"{domain} is not running")


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("all"))
@click.option(
    "-u", "--user", type=click.Choice([cnf.ssh.user, "root"]), default=cnf.ssh.user
)
@click.option("-s", "--start", is_flag=True, help="Start the domain before running SSH")
@need_ssh_agent
def ssh(domain: Domain, user: str = cnf.ssh.user, start: bool = False):
    """
    Connect to the domain over ssh.
    """
    environ["TERM"] = "xterm-256color"
    if domain.shutoff():
        if start:
            domain.start()
            domain.wait()
            domain.poststart()
            domain.ssh(user)
        else:
            error(f"{domain} is shutdown")
    else:
        domain.ssh(user)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.option("--user", type=click.Choice([cnf.ssh.user, "root"]), default=cnf.ssh.user)
@click.option("-s", "--start", is_flag=True, help="Start the domain before running SSH")
@need_ssh_agent
def sftp(domain: Domain, user: str = cnf.ssh.user, start: bool = False) -> None:
    """
    Connect to the domain over sftp.
    """
    if domain.shutoff():
        if start:
            domain.start()
            domain.wait()
            domain.poststart()
            domain.sftp(user)
        else:
            error(f"{domain} is shutdown")
    else:
        domain.sftp(user)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def proxy_cmd(domain: Domain) -> None:
    """
    Perform the command allowing to access the SSH port of the target
    domain.
    """
    local_exec(domain.proxy_cmd())


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("stopped"))
def rm(domain: Domain) -> Domain:
    """
    Remove the virtual machine and its associated disk.
    """

    if not domain.is_template():
        # Finding the volumes that are not associated to a template
        volumes = [
            vol
            for vol in domain.volumes()
            if not (
                vol.name
                in [
                    y.name
                    for y in chain.from_iterable(
                        [x.volumes() for x in get_template_domains()]
                    )
                ]
                or domain.is_template()
            )
        ]
    else:
        volumes = domain.volumes()

    if domain.running():
        error(f"{domain} is running")

    if volumes:
        if len(volumes) > 1:
            msg = "The operation will remove the following volumes:"
            msg += "".join([f"\n- {v.name}" for v in volumes])
        else:
            msg = f"The operation will remove the following volume:\n - {volumes[0]}"
        print(msg)
        inp = input("Do you confirm [y/N]: ")
        if inp != "y":
            error("Aborting")

    try:
        domain.remove(volumes)
    except Domain.UnassociatedVolume as e:
        error(str(e))
    except Domain.RemoveError as e:
        error(f"Error while removing {domain}: {e}")

    desktop_path = f"{HOME}/.local/share/applications/{domain}.desktop"
    if exists(desktop_path):
        remove(desktop_path)

    return domain


@__main__.command()
@click.option(
    "--format",
    default="ansible",
    type=click.Choice(["ansible", "ssh"]),
    help="Output format [ansible json inventory, ssh]",
)
def inventory(format: str = "ansible") -> None:
    """
    Return an ansible-compatible inventory of Libvirt virtual machines.
    """
    hosts: dict[str, Any] = {"_meta": {"hostvars": {}}}
    for domain in get_all_domains():
        domain.load_metadata()
        if not domain.managed:
            continue

        if format == "ansible":
            for tag in domain.tags:
                if tag not in hosts:
                    hosts[tag] = []

                hosts[tag].append(domain.name)

            if domain.distrib not in hosts:
                hosts[domain.distrib] = []

            hosts[domain.distrib].append(domain.name)

            ssh_options = (
                f"-o ProxyCommand='{__file__} {proxy_cmd.name} %h' "
                " -o CanonicalizeHostname=no"
            )
            hosts["_meta"]["hostvars"][domain.name] = {
                "ansible_host": domain.name,
                "ansible_ssh_common_args": ssh_options,
            }

        elif format == "ssh":
            print(
                (
                    f"Host {domain.name}\n"
                    f"\tUser {cnf.ssh.user}\n"
                    "\tPasswordAuthentication no\n"
                    f"\tIdentityFile {cnf.ssh.key}\n"
                    f"\tProxyCommand {__file__} {proxy_cmd.name} %h\n"
                    "\tCanonicalizeHostname=no\n"
                )
            )

    if format == "ansible":
        dump(hosts, stdout, indent=4)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def view(domain: Domain) -> None:
    """
    Run spicy on the target
    """
    if not exists("/usr/bin/spicy"):
        error("Please install spice-client-gtk")

    local_exec(f"/usr/bin/spicy -h 127.0.0.1 -p {domain.spice_port()}")


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
def view2(domain: Domain) -> None:
    """
    Run virt-viewer on the target
    """
    if not exists("/usr/bin/virt-viewer"):
        error("Please install virt-viewer")

    log.info("Resetting virt-viewer settings")
    virt_config_folder = f"{HOME}/.config/virt-viewer"
    if not exists(virt_config_folder):
        mkdir(virt_config_folder)
    with open(join(virt_config_folder, "settings"), "w") as fp:
        fp.write("[virt-viewer]\nask-quit=false\nshare-clipboard=false")
    environ["SPICE_NOGRAB"] = "1"  # viewer does not grab input
    local_exec(f"/usr/bin/virt-viewer -H release-cursor=ctrl+alt {domain}")


@__main__.command()
@click.argument("name", type=click.STRING)
@click.option(
    "-t",
    "--template",
    type=Type.domain,
    default=cnf.defaults.template.name,
    help="Template for the newly virtual machine to be based on",
    shell_complete=autocomplete("template"),
)
@click.option(
    "-d",
    "--description",
    default="",
    help="Short description of the virtual machine's purpose",
)
@click.option("--hostname", help="Set the newly-created virtual machine's hostname")
@click.option(
    "--network",
    default=f"{cnf.libvirt.network}",
    help="Set the newly-created virtual machine's network (format: LIBVIRT_NETWORK or none)",
)
@click.option(
    "-s",
    "--stopped",
    is_flag=True,
    help="Shut down the newly-created virtual machine after creation",
)
@click.option(
    "--no_randomize_hostname",
    is_flag=True,
    help="Do not randomize the newly-created virtual machine's name",
)
@click.option(
    "--no_shmem",
    is_flag=False,
    help="Disable memory backing with shared memory",
)
@click.option("--no_vsock", is_flag=False, help="Disable vsock for SSH")
@click.option(
    "--no_post_action",
    is_flag=False,
    help="Disable post actions after the installation",
)
@click.option(
    "--tags",
    type=click.STRING,
    default="",
    help="Tag to determine the post actions to perform",
)
@need_ssh_agent
def new(
    name: str,
    template: Domain,
    description: str = "",
    hostname: str = "",
    network: str = cnf.libvirt.network,
    stopped: bool = False,
    no_randomize_hostname: bool = False,
    no_shmem: bool = False,
    no_vsock: bool = False,
    no_post_action: bool = False,
    tags: str = "",  # the default from settings will be added later in the code
):
    """
    Create new virtual machine
    """

    if template.os == "windows":
        no_vsock = True

    log.info(f"New virtual machine name is {name}")
    try:
        domain = Domain.new(name, template, network, not no_shmem, not no_vsock)
    except Exception as e:
        error(str(e))
    log.success(f"Virtual machine {name} successfully created")

    if not no_post_action:
        log.info("Triggering post install actions")
        template_host_key = get_template_sshpubkey("template", template.name)
        if template_host_key is not None:
            log.info(f"Create SSH known_hosts entries for {domain.name}")
            configure_ssh_known_hosts(
                cnf.ssh.known_hosts_file, template_host_key, domain.name
            )
        log.info(f"Waiting for {domain.name} to be up")
        domain.wait(60, init_control_master=False)

        if no_randomize_hostname:
            hostname = domain.name
        else:
            if not hostname:
                hostname = randomize_hostname()
            domain.alias = hostname

        domain.description = description
        domain.tags = tags.split(",") if tags != "" else cnf.defaults.tags

        domain.set_metadata()

        # Running post `new` actions based on provided tags
        for tag in domain.tags:
            if tag in cnf.hooks and cnf.hooks[tag].new is not None:
                log.info(f"Running new hook: {tag}")
                cmd = (
                    f"{cnf.hooks[tag].new} {tag} {domain.name} "
                    f"{domain.os} {domain.distrib} {domain.alias}"
                )
                err, _, _ = local_run(cmd)
                if err:
                    log.warning(f"An error occurred during the hook execution: {tag}")

    if stopped:
        log.info(f"Stopping {name}")
        domain.stop()
    else:
        domain.poststart()

    log.success(f"{name} is ready")

    return domain


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.option(
    "-t", "--timeout", type=int, default=60, help="Timeout to wait before terminating"
)
def notify_when_up(domain: Domain, timeout: int = 60):
    """
    Send a desktop notification when the target domain is ready (i.e. SSH
    port accessible).
    """
    # double fork:
    if fork() == 0:
        if fork() == 0:
            domain.wait(timeout)
            raise SystemExit(1)
        else:
            sleep(timeout)
            raise SystemExit()


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("stopped"))
@click.argument("qcow2", type=click.Path(exists=False, file_okay=True))
def archive(domain: Domain, qcow2: str):
    """
    Copy the virtual machine's qcow2 file elsewhere and compress it.
    """
    if domain.running():
        error(f"{domain} is running, shutdown the virtual machine before archiving it")

    storage_files = domain.storage_files()
    for file in storage_files:
        if domain.name in file:
            log.info(f"Archiving {file}")
            local_exec(
                f"/usr/bin/virsh vol-download --pool {cnf.libvirt.pool} {file} --file {qcow2}"
            )


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.option("-f", "--foreground", is_flag=True, help="Run XPRA in foreground")
@click.option(
    "-u", "--user", type=click.Choice([cnf.ssh.user, "root"]), default=cnf.ssh.user
)
@need_ssh_agent
def xpra(domain: Domain, user: str = cnf.ssh.user, foreground: bool = False):
    """
    Run XPRA on the target domain.
    """
    if foreground:
        domain.graphics("xpra", user=user)
    else:
        # FIXME
        # local_exec(f"/usr/bin/systemctl --user start vm-xpra@{domain}")
        if "SSH_AUTH_SOCK" in environ:
            prop = f"--property=Environment=SSH_AUTH_SOCK={environ['SSH_AUTH_SOCK']}"
        err, _, _ = local_run(
            (
                f"/bin/systemd-run --user --collect --unit xpra-{domain} "
                f"--property=Restart=on-failure {prop} "
                f"--description='Client Xpra to {domain}' "
                f"-- mofos xpra -f {domain}"
            )
        )
        if err:
            error("Could not run the Xpra transient service")


# TODO: add a switch to retrieve the output
@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("all"))
@click.argument("command", type=click.STRING)
@click.option(
    "-u", "--user", type=click.Choice([cnf.ssh.user, "root"]), default=cnf.ssh.user
)
@click.option("-s", "--start", is_flag=True, help="Wait for the domain to boot")
@need_ssh_agent
def run(domain: Domain, command: str, user: str, start: bool):
    """
    Run a command on the domain over ssh.
    """
    if domain.shutoff():
        if start:
            domain.start()
            domain.wait()
            domain.poststart()
            domain.exec(command, user=user)
        else:
            error(f"{domain} is shutdown")
    else:
        domain.exec(command, user=user)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("stopped"))
@click.argument("new_name", type=click.STRING)
def rename(domain: Domain, new_name: str):
    """
    Rename the domain by new_name.
    """
    # Do the following actions:

    # - Rename the virDomain object
    # - Rename the associated disks
    # - Renew the desktop files
    raise NotImplementedError("Not implemented yet")
