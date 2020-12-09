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

AcmeCA Tests
------------

* TestAcmetinyCA: Tests the `Acmetiny <https://github.com/diafygi/acme-tiny>`_ client against the :class:`~acme_broker.server.AcmeCA`.
* TestCertBotCA: Tests the `Certbot <https://github.com/certbot/certbot>`_ client against the :class:`~acme_broker.server.AcmeCA`.
* TestOurClientCA: Tests the :class:`~acme_broker.client.AcmeClient` against the :class:`~acme_broker.server.AcmeCA`.
* TestDehydratedCA: tests the `Dehydrated <https://github.com/dehydrated-io/dehydrated>`_ client against the :class:`~acme_broker.server.AcmeCA`.

To run all of the tests:

.. code-block:: bash
    :substitutions:

    mkdir /tmp/dehydrated
    curl https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated -o /tmp/dehydrated/dehydrated
    chmod +x /tmp/dehydrated/dehydrated
    cd tests
    python -m unittest test_ca.py
