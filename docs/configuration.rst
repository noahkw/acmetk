Configuration
=======================================

Configuration of all ACME server types is done in YAML.
The config file is passed to the main script like so:

.. code-block:: bash

    python -m acme_broker run --config-file=/path/to/config_file.yaml


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

To run a CA that issues self-signed certificates, the private key
and root certificate may be generated using the following command:

.. code-block:: bash

    python -m acme_broker generate-keys /app/certs/root.key
