Development
===========

This chapter details how the package's tests are run and gives an overview of all base classes and public interfaces.

Tests
#####

The tests are run using the :py:mod:`unittest` framework.
Each test has a corresponding section in the :code:`debug.yml` that configures the tested apps.
The section's name is defined by the property :attr:`config_sec` that each test overrides.

To run any of these, the *acmetk* package first needs to be installed:

.. code-block:: bash
    :substitutions:

    git clone |GIT_URL|
    cd acmetk/
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
* This package's own client :class:`~acmetk.client.AcmeClient`
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

The *OurClient* (:class:`~acmetk.client.AcmeClient`) subclasses have the following additional test functions:

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

Tests the integration of the :class:`~acmetk.server.AcmeCA` against various test clients.

To run all of the tests:

.. code-block:: bash

    mkdir /tmp/dehydrated
    curl https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated -o /tmp/dehydrated/dehydrated
    chmod +x /tmp/dehydrated/dehydrated
    cd tests
    python -m unittest test_ca.py


AcmeBroker/AcmeProxy Tests
--------------------------

Tests the integration of the :class:`~acmetk.server.AcmeBroker`/:class:`~acmetk.server.AcmeProxy`
against two certificate authorities, namely a local :class:`~acmetk.server.AcmeCA` instance and
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

Tests the main functionality of the :class:`~acmetk.client.challenge_solver.InfobloxClient` to
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

Tests the :class:`acmetk.server.AcmeCA` behind a reverse proxy inside a docker container spun up by
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

Contributing
############

Set up your development environment:

.. code-block:: bash

    # Clone the repo
    git clone |GIT_URL|
    cd acmetk/
    # Create a virtual environment
    python -m venv venv
    source venv/bin/activate
    # Install the requirements
    pip install -r requirements.txt
    pip install -r requirements-dev.txt
    # Install the package in dev mode
    pip install -e .
    # Install the pre-commit hook for linting, formatting, etc.
    pre-commit install

Abstract Base Classes
#####################

AcmeServerBase
--------------

:class:`~acmetk.server.AcmeServerBase` is the base class for all ACME-compliant server implementations.
It encapsulates a :class:`aiohttp.web.Application` to respond to ACME requests and :code:`aiohttp_jinja2`
is used as the template engine to render the :class:`~acmetk.server.management.AcmeManagement`
and :class:`~acmetk.server.external_account_binding.AcmeEAB` sites.

Subclasses need to implement the methods :meth:`~acmetk.server.AcmeServerBase.certificate`
and :meth:`~acmetk.server.AcmeServerBase.handle_order_finalize`.
Subclasses must also set the :attr:`~acmetk.server.AcmeServerBase.config_name` which corresponds
to the section name in the config files.
Instances should only be created using :meth:`~acmetk.server.AcmeServerBase.create_app`
which instantiates the server and attaches the database session at the least.

To run a new server from the CLI, a :func:`run_servername` function, which is called if
:code:`app_class` is the server class, should be created in :mod:`acmetk.main.py`.
Any challenge validators, internal clients, etc., as well as the server itself, should be instantiated there.
The runner is then returned along with the server instance.

AcmeRelayBase
-------------

:class:`~acmetk.server.AcmeRelayBase` inherits from :class:`~acmetk.server.AcmeServerBase`.
It features an internal :class:`~acmetk.client.AcmeClient` that is used to communicate with another
certificate authority of choice.
Subclasses need to implement the method :meth:`~acmetk.server.AcmeServerBase.handle_order_finalize`.

If complex configuration beyond the server itself and its internal client is not needed, then the existing
:func:`run_relay` in :mod:`acmetk.main.py` may be used to start the server.

Challenge Solver
----------------

:class:`~acmetk.client.challenge_solver.ChallengeSolver` is the interface that challenge solver
plugins must implement.
Implementations must also be registered with the plugin registry via
:meth:`acmetk.server.PluginRegistry.register_plugin`, so that the CLI script knows which
configuration option corresponds to which challenge solver class.
A template for a challenge solver plugin can be found in :code:`acmetk/plugins/template_solver.py`.

:meth:`~acmetk.client.challenge_solver.ChallengeSolver.connect` may be overridden if the plugin
needs to connect to some resource before being able to challenge completion requests.

:meth:`~acmetk.client.challenge_solver.ChallengeSolver.complete_challenge` must be overridden by
all plugin implementations.
It is passed the account key, as well as the challenge and the identifier associated with the challenge.
Upon being called, the method needs to complete the challenge, i.e. by provisioning some resource,
and then defer returning until the remote CA is allowed to validate the challenge.

:meth:`~acmetk.client.challenge_solver.ChallengeSolver.complete_challenge` must also be overridden by
all plugin implementations.
Upon being called, it should de-provision the resources that were provisioned by the solver
to complete that specific challenge.

Configuration options inside the :code:`challenge_solver` section of the client's block
are directly passed to the constructor as keyword arguments.
If our sublass were called :code:`xyzdns`, for example, then :code:`host="example.xyz"` would be
passed in the following example:

.. code-block:: yaml

    client:
      challenge_solver:
        xyzdns:
          host: 'example.xyz'

Challenge Validator
-------------------

:class:`~acmetk.server.challenge_validator.ChallengeValidator` is the interface that challenge
validator plugins must implement.
Implementations must also be registered with the plugin registry via
:meth:`acmetk.server.PluginRegistry.register_plugin`, so that the CLI script knows which
configuration option corresponds to which challenge validator class.
A template for a challenge validator plugin can be found in :code:`acmetk/plugins/template_validator.py`

:meth:`~acmetk.server.challenge_validator.ChallengeValidator.validate_challenge` must be
overridden by all plugin implementations.
It is passed the challenge as well as any number of keyword arguments.
Upon being called, the method should attempt to validate the challenge.
If the validation was successful, then the method should just return.
Otherwise, a :class:`~acmetk.server.challenge_validator.CouldNotValidateChallenge`
exception must be raised.
