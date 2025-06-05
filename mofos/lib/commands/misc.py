import click
import logging


from mofos.lib.commands.main import __main__
from mofos.lib.kinds import Type, autocomplete
from mofos.lib.domain import Domain
from mofos.lib.utils import error
from mofos.lib.logger import VmLogger
from mofos.lib.spicex_client import SpiceXSession

log: VmLogger = logging.getLogger(__name__)  # type: ignore


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.argument("action", type=click.Choice(["list", "attach", "detach"]))
@click.argument("index", type=click.INT, default=0)
def spice(domain: Domain, action: str, index: int = 0):
    """
    List, attach or detach a USB device to the given domain.
    """
    if domain.shutoff():
        error(f"{domain} is not running")

    session = domain.spicex_session
    session.start()
    try:
        session.do_action(action, index)
    except SpiceXSession.FailedOperation:
        error("The operation failed")
    except SpiceXSession.InvalidMessageFormat as e:
        error(str(e))
    except SpiceXSession.MissingIndex as e:
        error(str(e))
    except SpiceXSession.AlreadyAttached as e:
        log.warning(e)
    except SpiceXSession.NotAttached as e:
        log.warning(e)


@__main__.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("running"))
@click.option("--description", type=click.STRING, help="New description")
@click.option("--alias", type=click.STRING, help="New alias hostname")
@click.option("--tags", type=click.STRING, help="Comma separated list of tags")
def metadata(domain: Domain, description: str, alias: str, tags: str):
    """
    Manage manually metadata.
    """

    domain.load_metadata()
    print(domain.name)
    print(domain.description)
    print(domain.alias)
    print(domain.tags)

    if description:
        domain.description = description
    if alias:
        domain.alias = alias
    if tags:
        domain.tags = tags.split(",")

    if description or alias or tags:
        domain.set_metadata()
