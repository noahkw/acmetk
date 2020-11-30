API
===

ACME Client
###########

.. autoclass:: acme_broker.client.AcmeClient
    :members:
    :inherited-members:

Challenge Solvers
-----------------

.. automodule:: acme_broker.client.challenge_solver
    :members:
    :inherited-members:

ACME Servers
############

ACME Server Base
----------------

.. autoclass:: acme_broker.server.AcmeServerBase
    :members:
    :inherited-members:

ACME Relay Base
---------------

.. autoclass:: acme_broker.server.AcmeRelayBase
    :members:
    :show-inheritance:

ACME Certificate Authority
--------------------------

.. autoclass:: acme_broker.server.AcmeCA
    :members:
    :show-inheritance:

ACME Broker
-----------

.. autoclass:: acme_broker.server.AcmeBroker
    :members:
    :show-inheritance:

ACME Proxy
----------

.. autoclass:: acme_broker.server.AcmeProxy
    :members:
    :show-inheritance:

Challenge Validators
--------------------

.. automodule:: acme_broker.server.challenge_validator
    :members:
    :inherited-members:

Models
######

Message types
-------------

.. automodule:: acme_broker.models.messages
    :members:
    :show-inheritance:

Database models
---------------

Account
^^^^^^^
.. autoclass:: acme_broker.models.account.Account
    :members:

Authorization
^^^^^^^^^^^^^
.. automodule:: acme_broker.models.authorization
    :members:

Certificate
^^^^^^^^^^^
.. autoclass:: acme_broker.models.certificate.Certificate
    :members:

Challenge
^^^^^^^^^
.. automodule:: acme_broker.models.challenge
    :members:

Identifier
^^^^^^^^^^
.. automodule:: acme_broker.models.identifier
    :members:

Order
^^^^^
.. autoclass:: acme_broker.models.order.Order
    :members:
