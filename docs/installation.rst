Installation
============

There are two supported installation methods: *bare-metal* and *docker*.

The bare-metal section focuses on deploying an :class:`~acmetk.server.AcmeBroker` with a PostgreSQL
instance on a virtual machine running Debian Stretch (9).
The section after that explains how to run this same setup behind an
`OpenResty reverse proxy <https://openresty.org/>`_.

The docker section deploys a :class:`~acmetk.server.AcmeProxy`, also with a PostgreSQL database, behind
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
   sudo useradd acmetk -m -d /srv/acmetk -s /bin/bash
   # create the configuration directory and grant permissions
   sudo mkdir /etc/acmetk && sudo chown acmetk: /etc/acmetk
   # change user to the newly created one
   sudo su acmetk
   # clone the repository to the user's home directory
   cd /srv/acmetk
   git clone |GIT_URL|


To create the database user and the database needed for the :class:`~acmetk.server.AcmeBroker`,
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

   # Log into user acmetk and change dir to its home directory
   sudo su acmetk
   cd
   # Create the virtual environment and activate it
   python -m venv venv
   source venv/bin/activate
   # Install the package into the virtual environment
   pip install -r acme-broker/requirements.txt
   pip install acme-broker/.
   # Generate an account key for the internal ACME client
   python -m acmetk generate-account-key /etc/acmetk/broker_client_account.key
   # Change the key's file permissions
   chmod 600 /etc/acmetk/broker_client_account.key

Copy the template config file :code:`conf/broker.config.sample.yml` and the systemd unit file
:code:`conf/broker.service` and edit them according to your use case.
For an explanation of the configuration options, see :ref:`config_broker_proxy`.

.. code-block:: bash

   cp acmetk/conf/broker.config.sample.yml /etc/acmetk/config.yml
   chmod 600 /etc/acmetk/config.yml
   exit
   sudo cp acmetk/conf/broker.service /etc/systemd/system

The final step is to initialize the db's tables and then enable/start the broker app:

.. code-block:: bash

   # Initialize the database's tables.
   # Enter the password you chose above when prompted.
   python -m acmetk db init postgresql+asyncpg://acme:{}@localhost:5432/acme
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

   cd /srv/acmetk
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

Update the dehydrated client script to the lastest version:

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

Build the :code:`acme/app` and :code:`acme/reverse_proxy` images locally:

.. code-block:: bash

   cd acme-broker/
   pwd # Should return the directory that the repo was cloned to
   sudo docker build -t acme/app -f app.Dockerfile .
   sudo docker build -t acme/reverse_proxy -f reverse_proxy.Dockerfile .

Create a directory that holds all the application data and configuration files, for example :code:`/home/acme`.
Copy the docker configuration files as well as the template config file :code:`conf/proxy.config.sample.yml` to it
and edit it the latter according to your use case.
For an explanation of the configuration options, see :ref:`config_broker_proxy`.

.. code-block:: yaml

   sudo mkdir /home/acme
   sudo chown -R $(whoami) /home/acme
   cp -r docker_conf /home/acme/etc
   mkdir /home/acme/etc/acme_server
   cp conf/proxy.config.sample.yml /home/acme/etc/acme_server/config.yml
   chmod 600 /home/acme/etc/acme_server/config.yml

Create a :code:`.env` file that holds the database user's (*acme_rw*) password defined in your :code:`config.yml`
and the path of said config file inside the container.
The initialization script also creates the users *acme_admin* and *acme_ro* with admin and read-only permissions
respectively.
*ACME_PREFIX* should contain the absolute path (without trailing slash) of the data directory that you created earlier.
The :code:`/home/acme/etc/acme_server` directory is mounted to :code:`/etc/acme_server` inside the container.

.. code-block:: ini

   ACME_SUPERUSER_PW=YOUR_SUPERUSER_PW
   ACME_ADMIN_PW=YOUR_ADMIN_PW
   ACME_RW_PW=YOUR_READ_WRITE_PW
   ACME_RO_PW=YOUR_READ_ONLY_PW
   ACME_PREFIX=/home/acme
   ACME_CONFIG_FILE=/etc/acme_server/config.yml

Generate an account key for the internal ACME client:

.. code-block:: bash

   sudo docker-compose run --entrypoint="" app python -m acmetk \
      generate-account-key /etc/acme_server/proxy_client_account.key
   # Change the key's file permissions
   sudo chmod 600 /home/acme/etc/acme_server/proxy_client_account.key

Initialize the db's tables as the *acme_admin* user and start the proxy as a daemon:

.. code-block:: bash

   # Initialize the database's tables.
   # Enter the password admin password specified in the .env file when prompted.
   sudo docker-compose run --entrypoint="" app python -m acmetk \
      db init postgresql+asyncpg://acme_admin:{}@db:5432/acme
   # Start the proxy as a daemon via docker-compose
   sudo docker-compose up -d

The proxy's directory should now be available at :code:`https://my-proxy.com/directory`.
It may take up to a minute after the first request until the proxy does not use the self-signed cert anymore,
because it needs to first acquire a valid cert signed by Let's Encrypt from the bootstrap proxy.
Supervisor's log files are mounted to :code:`./log` by default.

Post-installation
#################

ACME clients that are supposed to use the deployed ACME relay need to be pointed to the new directory now.
See :ref:`config_clients` for a guide on how to do this with a set of popular client implementations.
