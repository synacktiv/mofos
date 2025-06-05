import click
import logging

from os import environ
from sys import exit
from traceback import format_exc
from libvirt import registerErrorHandler  # type: ignore

from mofos.lib.logger import VmLogger

log: VmLogger = logging.getLogger(__name__)  # type: ignore


class Main(click.Group):
    def invoke(self, ctx):
        try:
            # Disabling libvirt errors
            def errorHandler(ctx, err):
                pass

            registerErrorHandler(errorHandler, None)

            return super().invoke(ctx)

        except click.exceptions.Exit:
            raise SystemExit()
        except KeyboardInterrupt:
            raise SystemExit(1)
        except Exception as exc:
            log.debug(format_exc().strip())
            log.error(exc)
            exit(1)


@click.group(cls=Main, context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--debug", is_flag=True, help="Debug mode for developers.")
@click.pass_context
def __main__(ctx, debug: bool = False):
    ctx.ensure_object(dict)

    from mofos.settings import config as cnf

    environ["LIBVIRT_DEFAULT_URI"] = cnf.libvirt.qemu
