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

The final step is to enable/start the broker app:

.. code-block:: bash

   sudo systemctl enable broker.service
   sudo systemctl start broker.service

The broker's directory should now be available at :code:`http://localhost:8000/directory`.

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

Docker
######

Install Docker and Docker Compose:

* `Install Docker Engine on Debian <https://docs.docker.com/engine/install/debian/>`_
* `Install Docker Compose <https://docs.docker.com/compose/install/>`_

Build the broker image locally:

.. code-block:: bash

   pwd # Should return the directory that the repo was cloned to
   sudo docker build -t broker_app .

Create a file :code:`config.yml`, copy the following template to it and edit it according to your use case.
For an explanation of the configuration options, see :ref:`config_broker_proxy`.

.. code-block:: yaml

    proxy:
      db: 'postgresql+asyncpg://acme:YOUR_PASSWORD@db:5432/acme'
      challenge_validator: 'requestipdns'
      rsa_min_keysize: 2048
      tos_url: 'https://my-proxy.com/tos'
      use_forwarded_header: true
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
        private_key: 'proxy_client_account.key'
        contact:
          phone: '555-1234'
          email: 'broker@my-proxy.com'
        challenge_solver:
          infoblox:
            host: 'ipam.my-proxy.com'
            username: 'infobloxuser'
            password: 'infobloxpassw'

The config file also needs a section that sets up logging.
For a configuration that should work for most use cases, see :ref:`config_logging`.

Create a :code:`.env` file that holds the database user's password defined in your :code:`config.yml` and the path of
said config file inside the container:

.. code-block:: ini

   ACME_BROKER_PG_PW=YOUR_PASSWORD
   ACME_BROKER_CONFIG_FILE=/app/config.yml

Generate an account key for the internal ACME client:

.. code-block:: bash

   sudo docker-compose run --entrypoint="" app python -m acme_broker generate-account-key /app/proxy_client_account.key
   # Change the key's file permissions
   sudo chmod 600 proxy_client_account.key

Acquiring an SSL certificate for the reverse proxy is out of this guide's scope, but the
full chain, private key, and dh param file should be located at :code:`./certs/fullchain.pem`,
:code:`./certs/client_cert.key`, and :code:`./certs/dhparam.pem` respectively.

Start the proxy as a daemon:

.. code-block:: bash

   sudo docker-compose up -d

The proxy's directory should now be available at :code:`https://my-proxy.com/directory`.
