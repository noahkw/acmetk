import logging
import os

import click

from acme_broker.server import AcmeCA

logger = logging.getLogger(__name__)


@click.group()
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], case_sensitive=False),
              default='INFO')
@click.option('--log-file', type=click.Path())
@click.pass_context
def main(ctx, log_level, log_file):
    logging.basicConfig(filename=log_file, level=log_level)


@main.command()
@click.option('--port', default=8000)
@click.option('--debug/--no-debug', default=False)
def ca(port, debug):
    """Starts the ACME CA"""
    click.echo(f'Starting ACME CA on port {port}')

    if not debug:
        acme_ca = AcmeCA()
        acme_ca.run(port=port)
    else:
        os.system(r'adev runserver server/server.py')


if __name__ == '__main__':
    main()
