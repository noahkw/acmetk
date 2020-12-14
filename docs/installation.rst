Installation
============

There are two supported installation methods: *bare-metal* and *docker*.

The bare-metal section focuses on deploying an :class:`~acme_broker.server.AcmeBroker` with a PostgreSQL
instance on a virtual machine running Debian Stretch (9).
The section after that explains how to run this same setup behind an
`OpenResty reverse proxy <https://openresty.org/>`_.

The docker section deploys a :class:`~acme_broker.server.AcmeProxy`, also with a PostgreSQL database, behind
an OpenResty reverse proxy.

Bare-metal
##########

Install PostgreSQL via apt:

.. code-block:: bash

   sudo apt update
   sudo apt install postgresql

The package requires at least Python version 3.8, which may or may not be available in apt's repositories.
To install it from source, follow the following guide (should work on Debian 9 or 10):
`How to install Python 3.8 on Debian 10 <https://linuxize.com/post/how-to-install-python-3-8-on-debian-10/>`_.

First, create the user that will run the broker app and clone the repository:

.. code-block:: bash
   :substitutions:

   # create the user
   sudo useradd acme_broker -m -d /srv/acme_broker -s /bin/bash
   # create the configuration directory and grant permissions
   sudo mkdir /etc/acme_broker && sudo chown acme_broker: /etc/acme_broker
   # change user to the newly created one
   sudo su acme_broker
   # clone the repository to the user's home directory
   cd /srv/acme_broker
   git clone |GIT_URL|


To create the database user and the database needed for the :class:`~acme_broker.server.AcmeBroker`,
issue the following commands:

.. code-block:: bash

   # Create the user
   sudo -u postgres createuser acme
   # Create the database
   sudo -u postgres createdb acme
   # Give the user a password
   sudo -u postgres psql
   # Issue the following commands inside the psql prompt
   postgres=$ ALTER USER acme WITH ENCRYPTED PASSWORD 'PASSWORD'; # Choose a strong password!
   # Grant the user privileges to access the database acme
   postgres=$ GRANT ALL PRIVILEGES ON DATABASE acme TO acme;

Now that the database is set up, we can set up the virtual environment, install the package and create
a configuration file for the broker.
Make sure to substitute :code:`python` with the python installation you want to use.
If it was installed via a package manager, then this is likely :code:`python3`.
If it was installed from source, for example following the guide linked above, then :code:`python3.8` probably
points to the right binary.

.. code-block:: bash

   # Log into user acme_broker and change dir to its home directory
   sudo su acme_broker
   cd
   # Create the virtual environment and activate it
   python -m venv venv
   source venv/bin/activate
   # Install the package into the virtual environment
   pip install -r acme-broker/requirements.txt
   pip install acme-broker/.
   # Generate an account key for the internal ACME client
   python -m acme_broker generate-account-key /etc/acme_broker/broker_client_account.key
   # Change the key's file permissions
   chmod 600 /etc/acme_broker/broker_client_account.key

Copy the template config file :code:`conf/broker.config.sample.yml` and the systemd unit file
:code:`conf/broker.service` and edit them according to your use case.
For an explanation of the configuration options, see :ref:`config_broker_proxy`.

.. code-block:: bash

   cp acme_broker/conf/broker.config.sample.yml /etc/acme_broker/config.yml
   chmod 600 /etc/acme_broker/config.yml
   exit
   sudo cp acme_broker/conf/broker.service /etc/systemd/system

The final step is to initialize the db's tables and then enable/start the broker app:

.. code-block:: bash

   # Initialize the database's tables.
   # Enter the password you chose above when prompted.
   python -m acme_broker db init postgresql+asyncpg://acme:{}@localhost:5432/acme
   # Enable/start the broker app's service
   sudo systemctl enable broker.service
   sudo systemctl start broker.service

The broker's directory should now be available at :code:`http://localhost:8180/directory`.

Bare-metal behind a reverse proxy
#################################

This section builds on the `Bare-metal`_ installation, so complete that first before continuing.

Install OpenResty from the openresty repository via apt: `Section Debian <http://openresty.org/en/linux-packages.html>`_

Copy the modified :code:`nginx.conf` as well as the broker site config file:

.. code-block:: bash

   cd /srv/acme_broker
   sudo cp acme-broker/conf/nginx.conf /etc/openresty/nginx.conf
   sudo mkdir /etc/openresty/conf.d
   sudo cp acme-broker/conf/broker_site.conf /etc/openresty/conf.d/

Now set the *use_forwarded_header* option to *true* in the broker's configuration file.

.. code-block:: ini

   use_forwarded_header: true

Install LuaRocks via apt and lua-resty-open-ssl via LuaRocks:

.. code-block:: bash

   sudo apt install luarocks
   sudo luarocks install lua-resty-auto-ssl
   # Create the config directory, grant permissions
   sudo mkdir /etc/resty-auto-ssl
   sudo chown www-data: /etc/resty-auto-ssl

Update the dehydrated client script to the latest version:

.. code-block::

   sudo curl https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated -o \
   /usr/local/bin/resty-auto-ssl/dehydrated

Generate the self-signed fallback certificate:

.. code-block:: bash

   sudo openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
      -subj '/CN=sni-support-required-for-valid-ssl' \
      -keyout /etc/ssl/resty-auto-ssl-fallback.key \
      -out /etc/ssl/resty-auto-ssl-fallback.crt

Copy the bootstrap broker systemd unit file, enable the service and start it.
Then restart the other services.

.. code-block:: bash

   sudo cp acme-broker/conf/broker_bootstrap.service /etc/systemd/system
   sudo systemctl enable broker_bootstrap.service
   sudo systemctl start broker_bootstrap.service
   sudo systemctl restart broker.service
   sudo systemctl restart openresty.service

The broker's directory should now be available at :code:`https://my-broker.com/directory`.
The bootstrap broker's directory is at :code:`http://localhost:8181/directory` and only accepts requests from
localhost.
The port is configurable in the :code:`broker_bootstrap.service` unit file.
If it is changed there, then OpenResty's :code:`nginx.conf` needs to be pointed to the correct
directory (line 25).

It may take up to a minute after the first request until the reverse proxy does not use the self-signed cert anymore,
because it needs to first acquire a valid cert signed by Let's Encrypt from the bootstrap broker.

Docker
######

Install Docker and Docker Compose:

* `Install Docker Engine on Debian <https://docs.docker.com/engine/install/debian/>`_
* `Install Docker Compose <https://docs.docker.com/compose/install/>`_

Clone the git repository:

.. code-block:: bash
   :substitutions:

   git clone |GIT_URL|

Build the broker image locally:

.. code-block:: bash

   cd acme-broker/
   pwd # Should return the directory that the repo was cloned to
   sudo docker build -t broker_app .

Create the directory :code:`./etc`, copy the template config file :code:`conf/proxy.config.sample.yml` to it
and edit it according to your use case.
For an explanation of the configuration options, see :ref:`config_broker_proxy`.

.. code-block:: yaml

   mkdir etc
   cp conf/proxy.config.sample.yml etc/config.yml
   chmod 600 etc/config.yml

Create a :code:`.env` file that holds the database user's (*acme_rw*) password defined in your :code:`config.yml`
and the path of said config file inside the container.
The initialization script also creates the users *acme_admin* and *acme_ro* with admin and read-only permissions
respectively.
The :code:`./etc` directory is mounted to :code:`/etc/acme_broker` inside the container.

.. code-block:: ini

   ACME_SUPERUSER_PW=YOUR_SUPERUSER_PW
   ACME_ADMIN_PW=YOUR_ADMIN_PW
   ACME_RW_PW=YOUR_READ_WRITE_PW
   ACME_RO_PW=YOUR_READ_ONLY_PW
   ACME_BROKER_CONFIG_FILE=/etc/acme_broker/config.yml

Generate an account key for the internal ACME client:

.. code-block:: bash

   sudo docker-compose run --entrypoint="" app python -m acme_broker \
      generate-account-key /etc/acme_broker/proxy_client_account.key
   # Change the key's file permissions
   sudo chmod 600 etc/proxy_client_account.key

Initialize the db's tables as the *acme_admin* user and start the proxy as a daemon:

.. code-block:: bash

   # Initialize the database's tables.
   # Enter the password admin password specified in the .env file when prompted.
   sudo docker-compose run --entrypoint="" app python -m acme_broker \
      db init postgresql+asyncpg://acme_admin:{}@db:5432/acme
   # Start the proxy as a daemon via docker-compose
   sudo docker-compose up -d

The proxy's directory should now be available at :code:`https://my-proxy.com/directory`.
It may take up to a minute after the first request until the proxy does not use the self-signed cert anymore,
because it needs to first acquire a valid cert signed by Let's Encrypt from the bootstrap proxy.
Supervisor's log files are mounted to :code:`./log` by default.

Post-installation
#################

When the ACME server is up and running, the clients need to be pointed to its directory URL.
This is achieved in different ways depending on the client and should be part of its documentation.
The following clients were tested against and are thus described here.

*
   `Acmetiny <https://github.com/diafygi/acme-tiny>`_: Simply set the argument :code:`--directory-url` when running the
   client:

   .. code-block:: bash

      acme-tiny --directory-url https://my-server.com/directory

*
   `Certbot <https://github.com/certbot/certbot>`_: Set the server option in the :code:`certbot.ini` and optionally
   set the config directory to avoid confusion as it is set to :code:`/etc/letsencrypt` by default.

   :code:`certbot.ini`:

   .. code-block:: ini

      server = https://my-server.com/directory
      config-dir = /etc/my_server_acme

*
   :class:`~acme_broker.client.AcmeClient`: Pass the directory URL when initializing the client object.

   .. code-block:: python

      from acme_broker.client import AcmeClient

      client = AcmeClient(
         directory_url="https://my-server.com/directory",
         private_key=...,
         contact=...,
      )

*
   `Dehydrated <https://github.com/dehydrated-io/dehydrated>`_: Set the CA option in the :code:`config` file and specify
   it when running dehydrated.

   :code:`./config`:

   .. code-block:: ini

      CA=https://my-server.com/directory

   .. code-block:: bash

      dehydrated --config ./config
