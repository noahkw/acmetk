Installation
============

There are two supported installation methods: *bare-metal* and *docker*.

The bare-metal section focuses on deploying an :class:`~acme_broker.server.AcmeBroker` with a PostgreSQL
instance on a virtual machine running Debian Stretch (9).
The section after that explains how to run this same setup behind an
`Nginx reverse proxy <https://www.nginx.com/>`_ in conjunction with
`Supervisor <http://supervisord.org/>`_.

The docker section deploys a :class:`~acme_broker.server.AcmeProxy`, also with a PostgreSQL database, behind an Nginx
reverse proxy.

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

   # create the user
   sudo -u postgres createuser acme
   # create the database
   sudo -u postgres createdb acme
   # give the user a password
   sudo -u postgres psql
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

   # log into user acme_broker and change dir to its home directory
   sudo su acme_broker
   cd
   # create the virtual environment and activate it
   python -m venv venv
   source venv/bin/activate
   # install the package into the virtual environment
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

   # Initialize the database's tables
   python -m acme_broker db init --config-file=/etc/acme_broker/config.yml
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
   # create the config directory, grant permissions
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

Restart both services:

.. code-block:: bash

   sudo systemctl restart broker.service
   sudo systemctl restart openresty.service

The broker's directory should now be available at :code:`https://my-broker.com/directory`.
It may take up to a minute after the first request until the proxy does not use the self-signed cert anymore.

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

Create a :code:`.env` file that holds the database user's password defined in your :code:`config.yml` and the path of
said config file inside the container.
The :code:`./etc` directory is mounted to :code:`/etc/acme_broker` inside the container:

.. code-block:: ini

   ACME_BROKER_PG_PW=YOUR_PASSWORD
   ACME_BROKER_CONFIG_FILE=/etc/acme_broker/config.yml

Generate an account key for the internal ACME client:

.. code-block:: bash

   sudo docker-compose run --entrypoint="" app python -m acme_broker \
      generate-account-key /etc/acme_broker/proxy_client_account.key
   # Change the key's file permissions
   sudo chmod 600 etc/proxy_client_account.key

Initialize the db's tables and start the proxy as a daemon:

.. code-block:: bash

   # Initialize the database's tables
   sudo docker-compose run --entrypoint="" app python -m acme_broker \
      db init --config-file=/etc/acme_broker/config.yml
   # Start the proxy as a daemon via docker-compose
   sudo docker-compose up -d

The proxy's directory should now be available at :code:`https://my-proxy.com/directory`.
It may take up to a minute after the first request until the proxy does not use the self-signed cert anymore.
Supervisor's log files are mounted to :code:`./logs` by default.
