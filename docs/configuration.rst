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

    service:
      type: ca
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
      eab:
        required: true
        type: plain
        header: x-user-email
      allow_wildcard: false

.. autopydantic_settings:: acmetk.server.AcmeCA.Config
   :inherited-members: BaseSettings
   :settings-show-json: False
   :settings-show-config-member: False
   :settings-show-config-summary: False
   :settings-show-validator-members: False
   :settings-show-validator-summary: False
   :field-list-validators: False

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
      eab:
        require: true
        type: plain
        header: x-user-email
      allow_wildcard: false
      client:
        directory: 'https://acme-v02.api.letsencrypt.org/directory'
        private_key: 'broker_client.key'
        contact:
          phone: '555-1234'
          email: 'brokerclient@mybroker.com'
        challenge_solver:
          type: rfc2136
          alg: hmac-sha512
          keyid: tsig-update-key
          secret: test
          server: 127.0.0.1
          dns_servers: ["127.1.2.3","127.2.3.4"]


.. autopydantic_settings:: acmetk.server.AcmeProxy.Config
   :inherited-members: BaseSettings
   :settings-show-json: False
   :settings-show-config-member: False
   :settings-show-config-summary: False
   :settings-show-validator-members: False
   :settings-show-validator-summary: False
   :field-list-validators: False


Refer to section `ACME Certificate Authority`_ for the options *hostname*, *port*, *db*, *challenge_validator*,
*rsa_min_keysize*, *ec_min_keysize*, *tos_url*, *mail_suffixes*, *subnets*, *use_forwarded_header*, *require_eab*,
and *allow_wildcard*.
The *client* section inside the main *broker* section configures the internal
:class:`~acmetk.client.AcmeClient` that is used to communicate with the actual CA.
Refer to section `ACME Client`_ for a description of the possible options.

Challenge Validator Plugins
###########################

Every type of ACME server app needs an internal challenge validators.
There are currently different types of challenge validators.
The standard challenge validators which are specified in

* :class:`~acmetk.server.challenge_validator.HTTP01ChallengeValidator` :code:`'http-01'` as defined in `RFC8555 - 8.3. HTTP Challenge <https://datatracker.ietf.org/doc/html/rfc8555#section-8.3>`

* :class:`~acmetk.server.challenge_validator.DNS01ChallengeValidator` :code:`'dns-01'`as defined in `RFC8555 - 8.4. DNS Challenge <https://datatracker.ietf.org/doc/html/rfc8555#section-8.4>`

* :class:`~acmetk.server.challenge_validator.TLSALPN01ChallengeValidator` :code:`'tls-alpn-01'` as defined in `RFC 8737 - 3. TLS with Application-Layer Protocol Negotiation (TLS ALPN) Challenge <https://datatracker.ietf.org/doc/html/rfc8737/#name-tls-with-application-layer->`

as well as non-standard validators

* :class:`~acmetk.server.challenge_validator.DummyValidator` :code:`'dummy'`

* :class:`~acmetk.server.challenge_validator.RequestIPDNSChallengeValidator` :code:`'requestipdns'`

The :class:`~acmetk.server.challenge_validator.DummyValidator` does not do any actual validation and should only
be used in testing, as it is inherently insecure.

The :class:`~acmetk.server.challenge_validator.RequestIPDNSChallengeValidator` may be used in university or
corporate environments where the *DNS-01*, *HTTP-01* or *TLS-ALPN-01* challenge are difficult to realize.
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


.. autopydantic_settings:: acmetk.client.AcmeClient.Config
   :inherited-members: BaseSettings
   :settings-show-json: False
   :settings-show-config-member: False
   :settings-show-config-summary: False
   :settings-show-validator-members: False
   :settings-show-validator-summary: False
   :field-list-validators: False


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
    type: dummy
    # There are no configuration options


Infoblox Client
---------------

The :class:`~acmetk.plugins.infoblox_solver.InfobloxClient` is a *DNS-01* challenge solver that integrates
with an `Infoblox <https://www.infoblox.com/>`_ instance to provision TXT records.

The *challenge_solver* :class:`~acmetk.plugins.infoblox_solver.InfobloxClient.Config` block might look as follows:

.. code-block:: yaml

  challenge_solver:
    type: infoblox
    host: 'ipam.uni-hannover.de'
    username: 'infobloxuser'
    password: 'infobloxpassw'
    dns_servers:
    - '8.8.8.8' # Google DNS
    - '1.1.1.1' # Cloudflare DNS
    views:
    - 'Extern'


.. autopydantic_settings:: acmetk.plugins.infoblox_solver.InfobloxClient.Config
   :inherited-members: BaseSettings
   :settings-show-json: False
   :settings-show-config-member: False
   :settings-show-config-summary: False
   :settings-show-validator-members: False
   :settings-show-validator-summary: False
   :field-list-validators: False


RFC2136 Client
--------------

:class:`~acmetk.plugins.rfc2136_solver.RFC2136Client` is a *DNS-01* challenge using TSIG dns updates.

The *challenge_solver* :class:`~acmetk.plugins.rfc2136_solver.RFC2136Client.Config` block might look as follows:

.. code-block:: yaml

  challenge_solver:
    type: rfc2136
    alg: hmac-sha512
    keyid: tsig-update-key
    secret: test
    server: 127.0.0.1
    dns_servers: ["127.1.2.3","127.2.3.4"]


.. autopydantic_settings:: acmetk.plugins.rfc2136_solver.RFC2136Client.Config
   :inherited-members: BaseSettings
   :settings-show-json: False
   :settings-show-config-member: False
   :settings-show-config-summary: False
   :settings-show-validator-members: False
   :settings-show-validator-summary: False
   :field-list-validators: False


Lexicon Client
--------------

:class:`~acmetk.plugins.lexicon_solver.LexiconChallengeSolver` is a *DNS-01* challenge using `lexicon-dns <https://github.com/dns-lexicon/dns-lexicon>`_.

The *challenge_solver* :class:`~acmetk.plugins.lexicon_solver.LexiconChallengeSolver.Config` block might look as follows:

.. code-block:: yaml

  challenge_solver:
    type: lexicon
    dns_servers: ["127.1.2.3","127.2.3.4"]
    provider_name: …
    provider_options: …


.. autopydantic_settings:: acmetk.plugins.lexicon_solver.LexiconChallengeSolver.Config
   :inherited-members: BaseSettings
   :settings-show-json: False
   :settings-show-config-member: False
   :settings-show-config-summary: False
   :settings-show-validator-members: False
   :settings-show-validator-summary: False
   :field-list-validators: False


Refer to the `lexicon documentation <https://dns-lexicon.github.io/dns-lexicon/configuration_reference.html#providers-options>`_ for provider_name and provider_options.


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
