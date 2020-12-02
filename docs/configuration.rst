Configuration
=======================================

Configuration of all ACME server app types is done in YAML.
The config file is passed to the main script like so:

.. code-block:: bash

    python -m acme_broker run --config-file=/path/to/config_file.yaml

A config file *always* consists of one block defining the app itself and
another block that is passed to Python's :mod:`logging` module.
Further configuration blocks may be required by challenge validator or
challenge solver plugins as outlined in .

.. TODO: link.

There are three types of apps that each require different options to
run: :class:`~acme_broker.server.AcmeCA`, :class:`~acme_broker.server.AcmeBroker`,
and :class:`~acme_broker.server.AcmeProxy`.

ACME Certificate Authority
##########################

An ACME CA configuration file might look as follows:

.. code-block:: yaml

    ca:
      db: 'postgresql+asyncpg://user:password@host:5432/db'
      cert: '/app/certs/root.crt'
      private_key: '/app/certs/root.key'
      challenge_validator: 'requestipdns'
      rsa_min_keysize: 2048
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
      reverse_proxy_host: 'my-ca.com'

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

* tos_url (optional): URL of the terms of service.
    Omitted from the directory if not specified.

* mail_suffixes (optional): Allowed suffixes for email addresses in the *contact* field during account creation.
    Defaults to allowing any suffix if not specified.

* subnets (optional): Allowed subnets for all requests. Must be in CIDR notation.
    Hosts with an IP that is not part of any of these get a *503 Forbidden* HTTP error.
    Defaults to allowing any subnet if not specified.

* reverse_proxy_host (optional): The reverse proxy's hostname. Required if deployed behind a reverse proxy.
    The reverse proxy's hostname is needed so the app can identify *X-Forwarded-For* header spoofing.
    Needs to be the FQDN of the actual host that clients connect to.

To run a CA that issues self-signed certificates, the private key
and root certificate may be generated using the following command:

.. code-block:: bash

    python -m acme_broker generate-keys /app/certs/root.key


ACME Broker/Proxy
#################

The ACME Broker and Proxy support the same set of configuration options.
The only difference is the name of the configuration block being
*broker* and *proxy* respectively.

For a broker, the file might looks as follows:

.. code-block:: yaml

    broker:
      db: 'postgresql+asyncpg://user:password@host:5432/db'
      challenge_validator: 'requestipdns'
      rsa_min_keysize: 2048
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
      reverse_proxy_host: 'my-broker.com'
      client:
        directory: 'https://acme-v02.api.letsencrypt.org/directory'
        private_key: 'broker_client.key'
        contact:
          phone: '555-1234'
          email: 'brokerclient@luis.uni-hannover.de'
        infoblox:
          host: 'ipam.uni-hannover.de'
          username: 'infobloxuser'
          password: 'infobloxpassw'

Refer to section `ACME Certificate Authority`_ for the options *db*, *challenge_validator*,
*rsa_min_keysize*, *tos_url*, *mail_suffixes*, and *subnets*.
The *client* section inside the main *broker* section configures the internal
:class:`~acme_broker.client.AcmeClient` that is used to communicate with the actual CA.
Refer to section `ACME Client`_ for a description of the possible options.

Challenge Validator Plugins
###########################

Every type of ACME server app needs an internal challenge validator.
There are currently two types of challenge validator, both of which do not require configuration:
:class:`~acme_broker.server.challenge_validator.DummyValidator` and
:class:`~acme_broker.server.challenge_validator.RequestIPDNSChallengeValidator`.
To use the former, set *challenge_validator* to :code:`'dummy'` in the server app's section in the config file.
For the latter put :code:`'requestipdns'`.

The :class:`~acme_broker.server.challenge_validator.DummyValidator` does not do any actual validation and should only
be used in testing, as it is inherently insecure.

The :class:`~acme_broker.server.challenge_validator.RequestIPDNSChallengeValidator` may be used in university or
corporate environments where the *DNS-01* or *HTTP-01* challenge are difficult to realize.
It does not validate any actual ACME challenge, but instead checks whether the DNS identifier that is
to be authorized resolves to the host's IP address that requested challenge validation via an A or AAAA record.
To achieve this, the *DNS-01* and *HTTP-01* challenge are repurposed, so that no further client-side configuration is
required.

ACME Client
###########

The ACME client is usually configured as a part of an :class:`~acme_broker.server.AcmeBroker`
or :class:`~acme_broker.server.AcmeProxy` app.

The *client* block inside the respective app's surrounding configuration block might look as follows:

.. code-block:: yaml

  client:
    directory: 'https://acme-v02.api.letsencrypt.org/directory'
    private_key: 'broker_client.key'
    challenge_solver:
      infoblox:
        host: 'ipam.uni-hannover.de'
        username: 'infobloxuser'
        password: 'infobloxpassw'
    contact:
      phone: '555-1234'
      email: 'brokerclient@luis.uni-hannover.de'

* directory (required): The directory URL of the ACME CA that the client should communicate with.
    Usually, this will be Let's Encrypt or a similar ACME CA that issues free Domain Validation certificates.

* private_key (required): The RSA private key in PEM format that is used to sign requests sent to the CA.
    May be generated with :code:`python -m acme_broker generate-keys`.

* challenge_solver (required): Contains the configuration for the plugin that completes challenges.
    Refer to `Challenge Solver Plugins`_ for a list of possible options.

* contact (optional): Contact information that is sent to the CA on account creation.
    Should contain a string *phone* with a phone number, a string *email* with an email address, or both.

Challenge Solver Plugins
########################

Each challenge solver plugin listed here is configured as a block inside the main *client* section.

Dummy Solver
------------

The :class:`~acme_broker.client.challenge_solver.DummySolver` is a mock solver mainly used in testing and does not
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

The :class:`~acme_broker.client.challenge_solver.InfobloxClient` is a *DNS-01* challenge solver that integrates
with an `Infoblox <https://www.infoblox.com/>`_ instance to provision TXT records.

The *challenge_solver* section inside the respective client's surrounding configuration block might look as follows:

.. code-block:: yaml

  challenge_solver:
    infoblox:
      host: 'ipam.uni-hannover.de'
      username: 'infobloxuser'
      password: 'infobloxpassw'
