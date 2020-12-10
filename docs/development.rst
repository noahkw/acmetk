Development
===========

This chapter details how the package's tests are run and gives an overview of all base classes and public interfaces.

Tests
#####

The tests are run using the :py:mod:`unittest` framework.
Each test has a corresponding section in the :code:`debug.yml` that configures the tested apps.
The section's name is defined by the property :attr:`config_sec` that each test overrides.

To run any of these, the *acme_broker* package first needs to be installed:

.. code-block:: bash
    :substitutions:

    git clone |GIT_URL|
    cd acme-broker/
    pip install .

Furthermore, a PostgreSQL instance needs to be running locally.
This is easily achieved using docker-compose:

Put the following :code:`docker-compose.yml` in :code:`~/acme-pg` or any other empty folder:

.. code-block:: yaml

    version: "2.1"
    services:
      db:
        image: postgres
        volumes:
          - ./db_data:/var/lib/postgresql/data
        environment:
          POSTGRES_PASSWORD: ${ACME_TESTS_PG_PW}
          POSTGRES_USER: acme-broker
        ports:
          - 55432:5432

Create a :code:`.env` file alongside it:

.. code-block:: ini

    ACME_TESTS_PG_PW=acme-broker-debug-pw

Create the *acme-ca* table:

.. code-block:: bash

    # Start the container
    sudo docker-compose up -d
    # Find out the container name
    sudo docker ps # The correct name should end in _db_1
    # Substitute NAME with the container's name
    sudo docker exec -it NAME createdb -U acme-broker acme-ca

Test clients
------------

The server implementations are all tested against the following clients:

* `Acmetiny <https://github.com/diafygi/acme-tiny>`_
* `Certbot <https://github.com/certbot/certbot>`_
* This package's own client :class:`~acme_broker.client.AcmeClient`
* `Dehydrated <https://github.com/dehydrated-io/dehydrated>`_

There is one :func:`test_run` test function per client that tests the general certificate acquisition process from
creating an account to downloading the certificate.

Furthermore, the *Certbot* subclasses have the following test functions:

*
    :func:`test_subdomain_revocation`: Acquires a certificate for the configured domain itself and for the subdomains
    :code:`dns.domain` as well as :code:`http.domain` setting the preferred challenge to *DNS-01* and *HTTP-01*
    respectively. The three resulting certificates are then revoked.
*
    :func:`test_skey_revocation`: Acquires a certificate for the configured domain and then revokes it, signing the
    request using the certificate's private key.
* :func:`test_renewal`: Acquires a certificate for the configured domain and then renews it.
* :func:`test_register`: Tests the account creation process.
* :func:`test_unregister`: Registers an account, then deactivates that account.

The *OurClient* (:class:`~acme_broker.client.AcmeClient`) subclasses have the following additional test functions:

* :func:`test_run_stress`: Carries out ten general certificate acquisition processes in parallel.
*
    :func:`test_revoke`: Acquires a certificate for the configured domain and then revokes it, signing the
    request using the account's private key.
* :func:`test_account_update`: Registers an account, then updates the associated contact information.
*
    :func:`test_email_validation`: Registers an account, then updates the associated contact information specifying an
    email address with a suffix that is not whitelisted.
* :func:`test_unregister`: Registers an account, then deactivates that account.

AcmeCA Tests
------------

Tests the integration of the :class:`~acme_broker.server.AcmeCA` against various test clients.

To run all of the tests:

.. code-block:: bash

    mkdir /tmp/dehydrated
    curl https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated -o /tmp/dehydrated/dehydrated
    chmod +x /tmp/dehydrated/dehydrated
    cd tests
    python -m unittest test_ca.py


AcmeBroker/AcmeProxy Tests
--------------------------

Tests the integration of the :class:`~acme_broker.server.AcmeBroker`/:class:`~acme_broker.server.AcmeProxy`
against two certificate authorities, namely a local :class:`~acme_broker.server.AcmeCA` instance and
`Let's Encrypt staging <https://letsencrypt.org/docs/staging-environment/>`_.
The integration with the various clients is tested at the same time.
There is one caveat: The :class:`TestBrokerLE`/:class:`TestProxyLE` subclasses, meaning those that test against
LE staging, need to be run from a machine that has write access to, in our case, the Infoblox instance.
This may differ depending on which challenge solver plugin is used.

To run all of the tests:

.. code-block:: bash

    cd tests
    # AcmeBroker
    python -m unittest test_broker.py
    # AcmeProxy
    python -m unittest test_proxy.py

InfobloxClient Tests
--------------------

Tests the main functionality of the :class:`~acme_broker.client.challenge_solver.InfobloxClient` to
set and delete DNS TXT records.
The credentials except for the password need to be stored inside the *infoblox* section of the :code:`debug.yml`.
The DNS servers and default views should also be changed to be compatible with the individual infrastructure.

To run all of the tests:

.. code-block::

    cd tests
    echo "YOUR_PASSWORD" > ../infoblox
    # Create the file that contains the Infoblox password
    python -m unittest test_infoblox.py

Deployment Tests
----------------

Tests the :class:`acme_broker.server.AcmeCA` behind a reverse proxy inside a docker container spun up by
docker-compose.
To configure running these tests, PyCharm's docker-compose remote python interpreter functionality may be
leveraged.
Steps to create a remote interpreter these tests can run in:

* Click *Python 3.x (Venv name)* in the bottom right corner and select *Add Interpreter...*
* Select docker-compose on the left side in the new window
* Add *docker-compose.dev.yml* as a second configuration file
* Select *app* as the service
* Click OK

To run all of the tests:

First, create a new :code:`.env` file with the following contents in the repository's root folder.

.. code-block:: ini

    ACME_SUPERUSER_PW=acmesupw

Select the new docker-compose interpreter from the bottom right, right click *test_deployment.py* in the project view
and select "Run 'Unittests' in test_deployment.py".
