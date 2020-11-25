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

* db (required): The database connection string.
    At the moment, only PostgreSQL is supported.

* cert (required): Path to the CA's root certificate.
    Included with client certificates on certificate retrieval.

* private_key (required): Private key that corresponds to the root cert.
    Used to sign client certificates.

* rsa_min_keysize (optional): The minimum supported keysize for CSR and account RSA keys.
    Defaults to *2048* if not specified.

* tos_url (optional): URL of the terms of service.
    Omitted from the directory if not specified.

* mail_suffixes (optional): Allowed suffixes for email addresses in the *contact* field during account creation.
    Defaults to allowing any suffix if not specified.

* subnets (optional): Allowed subnets for all requests. Must be in CIDR notation.
    Hosts with an IP that is not part of any of these get a *503 Forbidden* HTTP error.
    Defaults to allowing any subnet if not specified.

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
      client:
        directory: 'https://acme-v02.api.letsencrypt.org/directory'
        private_key: 'broker_client.key'
        contact:
          phone: '555-1234'
          email: 'brokerclient@luis.uni-hannover.de'

Refer to section `ACME Certificate Authority`_ for the options *db*, *rsa_min_keysize*,
*tos_url*, *mail_suffixes*, and *subnets*.
The *client* section inside the main *broker* section configures the internal
:class:`~acme_broker.client.AcmeClient` that is used to communicate with the actual CA.
Refer to section `ACME Client`_ for a description of the possible options.

ACME Client
###########

The ACME client is usually configured as a part of an :class:`~acme_broker.server.AcmeBroker`
or :class:`~acme_broker.server.AcmeProxy` app.

The *client* block inside the respective app's surrounding configuration block might look as follows:

.. code-block:: yaml

  client:
    directory: 'https://acme-v02.api.letsencrypt.org/directory'
    private_key: 'broker_client.key'
    contact:
      phone: '555-1234'
      email: 'brokerclient@luis.uni-hannover.de'

* directory (required): The directory URL of the ACME CA that the client should communicate with.
    Usually, this will be Let's Encrypt or a similar ACME CA that issues free Domain Validation certificates.

* private_key (required): The RSA private key in PEM format that is used to sign requests sent to the CA.
    May be generated with :code:`python -m acme_broker generate-keys`.

* contact (optional): Contact information that is sent to the CA on account creation.
    Should contain a string *phone* with a phone number, a string *email* with an email address, or both.
