import click
import logging

from os.path import exists, isdir

from mofos.lib.commands.main import __main__
from mofos.lib.kinds import Type, autocomplete, need_ssh_agent
from mofos.lib.domain import Domain
from mofos.lib.utils import error
from mofos.lib.logger import VmLogger
from mofos.settings import config as cnf

log: VmLogger = logging.getLogger(__name__)  # type: ignore


@__main__.command()
@click.argument("source", type=click.Path(exists=True, file_okay=True))
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.option(
    "-d",
    "--dir",
    default=".",
    help="Remote destination directory (default: .)",
)
@click.option("--user", type=click.Choice([cnf.ssh.user, "root"]), default=cnf.ssh.user)
@need_ssh_agent
def push(source: str, domain: Domain, dir: str = ".", user: str = cnf.ssh.user) -> None:
    """
    Copy a file and send it to the target domain over SSH.
    """
    if not exists(source):
        error(f"Cannot access '{source}': No such file or directory")

    domain.scp(source, dir, user=user, is_dir=isdir(source), push=True)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("source", type=click.STRING)
@click.option(
    "-d",
    "--dir",
    type=click.Path(exists=True, dir_okay=True),
    default=".",
    help="Local destination directory (default: .)",
)
@click.option("--user", type=click.Choice([cnf.ssh.user, "root"]), default=cnf.ssh.user)
@need_ssh_agent
def pull(domain: Domain, source: str, dir: str = ".", user: str = cnf.ssh.user) -> None:
    """
    Copy a from a source domain over SSH.
    """
    if not exists(dir):
        error(f"Cannot access '{dir}': No such directory")

    domain.scp(source, dir, user=user, is_dir=True, push=False)


@__main__.command()
@click.argument("item", type=click.STRING)
@click.argument("source", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("destination", type=Type.domain, shell_complete=autocomplete("running"))
@click.option(
    "-r",
    "--recurse",
    is_flag=True,
    help="Item is a directory",
)
@click.option(
    "-d",
    "--dir",
    default=".",
    help="Remote destination directory (default: .)",
)
@click.option("--user", type=click.Choice([cnf.ssh.user, "root"]), default=cnf.ssh.user)
@need_ssh_agent
def copy(
    item: str,
    source: Domain,
    destination: Domain,
    recurse: bool = False,
    dir: str = ".",
    user: str = cnf.ssh.user,
) -> None:
    """
    Copy a from a source domain over SSH to another domain.
    """
    source.scp(item, dir, user=user, is_dir=recurse, push=False, remote=destination)
