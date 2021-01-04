Configuration
=======================================

Configuration of all ACME server app types is done in YAML.
The config file is passed to the main script like so:

.. code-block:: bash

    python -m acmetk run --config-file=/path/to/config_file.yaml

A config file *always* consists of one block defining the app itself and
another block that is passed to Python's :mod:`logging` module.

There are three types of apps that each require different options to
run: :class:`~acmetk.server.AcmeCA`, :class:`~acmetk.server.AcmeBroker`,
and :class:`~acmetk.server.AcmeProxy`.

ACME Certificate Authority
##########################

An ACME CA configuration file might look as follows:

.. code-block:: yaml

    ca:
      hostname: '127.0.0.1'
      port: 8000
      db: 'postgresql+asyncpg://user:password@host:5432/db'
      cert: '/app/certs/root.crt'
      private_key: '/app/certs/root.key'
      challenge_validator: 'requestipdns'
      rsa_min_keysize: 2048
      ec_min_keysize: 256
      tos_url: 'https://my-ca.com/tos'
      mail_suffixes:
        - 'uni-hannover.de'
        - 'tib.eu'
      subnets:
        - '127.0.0.1/32'
        - '10.0.0.0/8'
        - '172.16.0.0/12'
        - '192.168.0.0/16'
        - '130.75.0.0/16'
      use_forwarded_header: true
      require_eab: true

* hostname (optional): The hostname that the server should bind to. Required if the *path* option is omitted when starting the server from the CLI.
    May also be an IP.

* port (optional): The TCP port that the server should bind to. Required if the *path* option is omitted when starting the server from the CLI.
    May require root permissions to bind to a privileged port below 1024. In that case, deployment behind a reverse proxy is advised.

* db (required): The database connection string.
    At the moment, only PostgreSQL is supported.

* cert (required): Path to the CA's root certificate.
    Included with client certificates on certificate retrieval.

* private_key (required): Private key that corresponds to the root cert.
    Used to sign client certificates.

* challenge_validator (required): The plugin that validates challenges.
    Refer to `Challenge Validator Plugins`_ for a list of possible options.

* rsa_min_keysize (optional): The minimum supported keysize for CSR and account RSA keys.
    Defaults to *2048* if not specified.

* ec_min_keysize (optional): The minimum supported keysize for CSR EC keys. Account EC keys are currently not supported.
    Defaults to *256* if not specified.

* tos_url (optional): URL of the terms of service.
    Omitted from the directory if not specified.

* mail_suffixes (optional): Allowed suffixes for email addresses in the *contact* field during account creation.
    Defaults to allowing any suffix if not specified.

* subnets (optional): Allowed subnets for all requests. Must be in CIDR notation.
    Hosts with an IP that is not part of any of these get a *503 Forbidden* HTTP error.
    Defaults to allowing any subnet if not specified.

* use_forwarded_header (optional): Whether to read the host IP from the *X-Forwarded-For* header. Required if deployed behind a reverse proxy.
    Needed so the app can identify *X-Forwarded-For* header spoofing.

* require_eab (optional): Whether to require an External Account Binding on account creation.
    Defaults to allowing account creation without EAB if not specified.

To run a CA that issues self-signed certificates, the private key
and root certificate may be generated using the following command:

.. code-block:: bash

    python -m acmetk generate-keys /app/certs/root.key

.. _config_broker_proxy:

ACME Broker/Proxy
#################

The ACME Broker and Proxy support the same set of configuration options.
The only difference is the name of the configuration block being
*broker* and *proxy* respectively.

For a broker, the file might looks as follows:

.. code-block:: yaml

    broker:
      hostname: '127.0.0.1'
      port: 8000
      db: 'postgresql+asyncpg://user:password@host:5432/db'
      challenge_validator: 'requestipdns'
      rsa_min_keysize: 2048
      ec_min_keysize: 256
      tos_url: 'https://my-broker.com/tos'
      mail_suffixes:
        - 'uni-hannover.de'
        - 'tib.eu'
      subnets:
        - '127.0.0.1/32'
        - '10.0.0.0/8'
        - '172.16.0.0/12'
        - '192.168.0.0/16'
        - '130.75.0.0/16'
      use_forwarded_header: true
      require_eab: true
      client:
        directory: 'https://acme-v02.api.letsencrypt.org/directory'
        private_key: 'broker_client.key'
        contact:
          phone: '555-1234'
          email: 'brokerclient@mybroker.com'
        challenge_solver:
          infoblox:
            host: 'ipam.uni-hannover.de'
            username: 'infobloxuser'
            password: 'infobloxpassw'
            dns_servers:
              - '8.8.8.8' # Google DNS
              - '1.1.1.1' # Cloudflare DNS

Refer to section `ACME Certificate Authority`_ for the options *hostname*, *port*, *db*, *challenge_validator*,
*rsa_min_keysize*, *ec_min_keysize*, *tos_url*, *mail_suffixes*, *subnets*, *use_forwarded_header*,
and *require_eab*.
The *client* section inside the main *broker* section configures the internal
:class:`~acmetk.client.AcmeClient` that is used to communicate with the actual CA.
Refer to section `ACME Client`_ for a description of the possible options.

Challenge Validator Plugins
###########################

Every type of ACME server app needs an internal challenge validator.
There are currently two types of challenge validator, both of which do not require configuration:
:class:`~acmetk.server.challenge_validator.DummyValidator` and
:class:`~acmetk.server.challenge_validator.RequestIPDNSChallengeValidator`.
To use the former, set *challenge_validator* to :code:`'dummy'` in the server app's section in the config file.
For the latter put :code:`'requestipdns'`.

The :class:`~acmetk.server.challenge_validator.DummyValidator` does not do any actual validation and should only
be used in testing, as it is inherently insecure.

The :class:`~acmetk.server.challenge_validator.RequestIPDNSChallengeValidator` may be used in university or
corporate environments where the *DNS-01* or *HTTP-01* challenge are difficult to realize.
It does not validate any actual ACME challenge, but instead checks whether the DNS identifier that is
to be authorized resolves to the host's IP address that requested challenge validation via an A or AAAA record.
To achieve this, the *DNS-01* and *HTTP-01* challenge are repurposed, so that no further client-side configuration is
required.

External Account Binding
########################

External Account Binding is an optional feature which requires that new ACME accounts be bound to an external account
via some mechanism outside of the ACME specification, see :ref:`config_clients_eab`.
ACME servers may be configured to require an external account binding for new registrations by setting
:code:`require_eab: true` in the configuration file.

Furthermore, the ACME server needs to be run behind a reverse proxy that verifies the user's SSL client certificate
and passes it to the server via the *X-SSL-CERT* header.
The provided Nginx/Openresty configuration files already contain the necessary directives to enable SSL client certs.
Uncomment lines 60 - 63 of your :code:`broker_site.conf`/:code:`app.conf`, so the section looks as follows:

.. code-block:: ini

    ssl_client_certificate /etc/ssl/trusted_roots.pem;
    ssl_verify_client optional;
    ssl_verify_depth 3;

Point :code:`ssl_client_certificate` to a text file that contains all PEM encoded intermediates and
the root certificate (at the very bottom) needed to verify the client certificates.
:code:`ssl_verify_depth` should be equal or greater than the number of certificates in the chain of trust, including the
root cert.

ACME Client
###########

The ACME client is usually configured as a part of an :class:`~acmetk.server.AcmeBroker`
or :class:`~acmetk.server.AcmeProxy` app.

The *client* block inside the respective app's surrounding configuration block might look as follows:

.. code-block:: yaml

  client:
    directory: 'https://acme-v02.api.letsencrypt.org/directory'
    private_key: 'broker_client.key'
    challenge_solver:
      infoblox:
        host: 'ipam.my-broker.com'
        username: 'infobloxuser'
        password: 'infobloxpassw'
        dns_servers:
          - '8.8.8.8' # Google DNS
          - '1.1.1.1' # Cloudflare DNS
    contact:
      phone: '555-1234'
      email: 'broker@my-broker.com'

* directory (required): The directory URL of the ACME CA that the client should communicate with.
    Usually, this will be Let's Encrypt or a similar ACME CA that issues free Domain Validation certificates.

* private_key (required): The RSA private key in PEM format that is used to sign requests sent to the CA.
    May be generated with :code:`python -m acmetk generate-keys`.

* challenge_solver (required): Contains the configuration for the plugin that completes challenges.
    Refer to `Challenge Solver Plugins`_ for a list of possible options.

* contact (optional): Contact information that is sent to the CA on account creation.
    Should contain a string *phone* with a phone number, a string *email* with an email address, or both.

Challenge Solver Plugins
########################

Each challenge solver plugin listed here is configured as a block inside the main *client* section.

Dummy Solver
------------

The :class:`~acmetk.client.challenge_solver.DummySolver` is a mock solver mainly used in testing and does not
require any configuration.
However, it should not be used in production as it does not actually solve any challenges, it only logs
its "attempts" and pauses execution for a second.
To configure a client to use it, set up the *challenge_solver* section inside the surrounding client configuration
block as follows:

.. code-block:: yaml

  challenge_solver:
    dummy:
    # There are no configuration options


Infoblox Client
---------------

The :class:`~acmetk.client.challenge_solver.InfobloxClient` is a *DNS-01* challenge solver that integrates
with an `Infoblox <https://www.infoblox.com/>`_ instance to provision TXT records.

The *challenge_solver* section inside the respective client's surrounding configuration block might look as follows:

.. code-block:: yaml

  challenge_solver:
    infoblox:
      host: 'ipam.uni-hannover.de'
      username: 'infobloxuser'
      password: 'infobloxpassw'
      dns_servers:
        - '8.8.8.8' # Google DNS
        - '1.1.1.1' # Cloudflare DNS
      views:
        - 'Extern'

The options *host*, *username*, and *password* are required and depend on the Infoblox instance's configuration.

* dns_servers (optional): List of IP addresses of the DNS servers that are queried to determine when the remote CA should validate the challenge.
    Defaults to :attr:`~acmetk.client.challenge_solver.InfobloxClient.DEFAULT_DNS_SERVERS` if omitted.

* views (optional): List of views to set the record in.
    Defaults to :attr:`~acmetk.client.challenge_solver.InfobloxClient.DEFAULT_VIEWS` if omitted.

.. _config_logging:

Logging
#######

The config section that is passed to :py:func:`logging.config.dictConfig` should be appended to the end of the config file.
An example logging section that should work for most scenarios looks as follows:

.. code-block:: yaml

    logging:
      version: 1
      formatters:
        simple:
          format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        simple_root:
          format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
      handlers:
        console:
          class: logging.StreamHandler
          level: INFO
          formatter: simple
          stream: ext://sys.stdout
        root_console:
          class: logging.StreamHandler
          level: INFO
          formatter: simple_root
          stream: ext://sys.stdout
      loggers:
        asyncio:
          level: ERROR
          handlers: [console]
          propagate: no
        acmetk:
          level: INFO
          handlers: [console]
          propagate: no
        acme.client:
          level: INFO
          handlers: [console]
          propagate: no
        aiohttp.access:
          level: INFO
          handlers: [console]
          propagate: no
        aiohttp.client:
          level: INFO
          handlers: [console]
          propagate: no
        aiohttp.internal:
          level: INFO
          handlers: [console]
          propagate: no
        aiohttp.server:
          level: INFO
          handlers: [console]
          propagate: no
        aiohttp.web:
          level: INFO
          handlers: [console]
          propagate: no
      root:
        level: INFO
        handlers: [root_console]
      disable_existing_loggers: no
