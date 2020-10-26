import asyncio
import logging
import os

import click
import click_config_file

from acme_broker.server import AcmeCA

logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
def main(ctx):
    pass


@main.command()
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], case_sensitive=False),
              default='INFO')
@click_config_file.configuration_option()
@click.option('--log-file', type=click.Path())
@click.option('--port', default=8000)
@click.option('--debug/--no-debug', default=False)
@click.option('--db-user')
@click.option('--db-pass')
@click.option('--db-host')
@click.option('--db-port')
@click.option('--db-database')
def ca(log_level, log_file, port, debug, db_user, db_pass, db_host, db_port, db_database):
    """Starts the ACME CA"""
    click.echo(f'Starting ACME CA on port {port}')

    logging.basicConfig(filename=log_file, level=log_level)
    logging.debug("""Passed Args: Log level '%s'
                        Log file '%s', 
                        Port '%d', 
                        Debug '%s',
                        DB-user '%s',
                        DB-pass '%s',
                        DB-host '%s',
                        DB-port '%d',
                        DB-database '%s'""", log_level, log_file, port, debug, db_user, '***' if db_pass else None,
                  db_host, db_port, db_database)

    if not debug:
        async def serve_forever():
            _ = await AcmeCA.runner(log_level=log_level, log_file=log_file, port=port, debug=debug,
                                    db_user=db_user, db_pass=db_pass, db_host=db_host, db_port=db_port,
                                    db_database=db_database)

            while True:
                await asyncio.sleep(3600)

        asyncio.run(serve_forever())
    else:
        # TODO: fix or remove
        os.system(r'adev runserver server/server.py')


if __name__ == '__main__':
    main()
