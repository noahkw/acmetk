Installation
============

There are two supported installation methods: *bare-metal* and *docker*.

The bare-metal section focuses on deploying an :class:`~acme_broker.server.AcmeBroker` with a PostgreSQL
instance on a virtual machine running Debian Stretch (9).
The section after that explains how to run this same setup behind an
`Nginx reverse proxy <https://www.nginx.com/>`_ in conjunction with
`Supervisor <http://supervisord.org/>`_.

The docker section deploys a :class:`~acme_broker.server.AcmeCA`, also with a PostgreSQL database, behind an Nginx
reverse proxy.

In either case, the first step is to clone the repository:

.. code-block:: bash
   :substitutions:

   git clone |GIT_URL|
   cd acme-broker

Bare-metal
##########

Install PostgreSQL via apt:

.. code-block:: bash

   sudo apt update
   sudo apt install postgresql

The package requires at least Python version 3.8, which may or may not be available in apt's repositories.
To install it from source, follow the following guide (should work on Debian 9 or 10):
`How to install Python 3.8 on Debian 10 <https://linuxize.com/post/how-to-install-python-3-8-on-debian-10/>`_.

To create the database user and the database needed for the :class:`~acme_broker.server.AcmeBroker`,
issue the following commands:

.. code-block:: bash

   # create the user
   sudo -u postgres createuser acme
   # create the database
   sudo -u postgres createdb acme
   # give the user a password
   sudo -u postgresql psql
   # issue the following commands inside the psql prompt
   postgres=$ ALTER USER acme WITH ENCRYPTED PASSWORD 'PASSWORD'; # choose a strong password
   # grant the user privileges to access the database acme
   postgres=$ GRANT ALL PRIVILEGES ON DATABASE acme TO acme;

Now that the database is set up, we can set up the virtual environment, install the package and create
a configuration file for the broker.
Make sure to substitute :code:`python` with the python installation you want to use.
If it was installed via a package manager, then this is likely :code:`python3`.
If it was installed from source, for example following the guide linked above, then :code:`python3.8` probably
points to the right binary.

.. code-block:: bash

   pwd # Should return the directory that the repo was cloned to
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install .
   # Generate an account key for the internal ACME client
   python -m acme_broker generate-account-key broker_client_account.key
   # Change the key's file permissions
   chmod 600 broker_client_account.key

Create a file *config.yml*, copy the following template to it and edit it according to your use case.
For an explanation of the configuration options, see :ref:`config_broker_proxy`.

.. code-block:: yaml

    broker:
      hostname: '127.0.0.1'
      port: 8000
      db: 'postgresql+asyncpg://acme:YOUR_PASSWORD@localhost:5432/acme'
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
      client:
        directory: 'https://acme-v02.api.letsencrypt.org/directory'
        private_key: 'broker_client_account.key'
        contact:
          phone: '555-1234'
          email: 'broker@my-broker.com'
        challenge_solver:
          infoblox:
            host: 'ipam.my-broker.com'
            username: 'infobloxuser'
            password: 'infobloxpassw'

The config file also needs a section that sets up logging.
For a configuration that should work for most use cases, see :ref:`config_logging`.

The final step is to start the broker server:

.. code-block:: bash

   python -m acme_broker run --config-file=config.yml

The broker's directory should now be available at :code:`http://localhost:8000/directory`.

Bare-metal behind a reverse proxy
#################################

Install

Docker
######
