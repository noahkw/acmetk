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

External Account Binding
------------------------

.. autoclass:: acme_broker.server.external_account_binding.ExternalAccountBinding
    :members:

.. autoclass:: acme_broker.server.external_account_binding.ExternalAccountBindingStore
    :members:

.. autoclass:: acme_broker.server.external_account_binding.AcmeEAB
    :members:

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
.. autoclass:: acme_broker.models.authorization.Authorization
    :members:

Certificate
^^^^^^^^^^^
.. autoclass:: acme_broker.models.certificate.Certificate
    :members:

Challenge
^^^^^^^^^
.. autoclass:: acme_broker.models.challenge.Challenge
    :members:

.. autoclass:: acme_broker.models.challenge.ChallengeType
    :members:

Identifier
^^^^^^^^^^
.. automodule:: acme_broker.models.identifier
    :members:

Order
^^^^^
.. autoclass:: acme_broker.models.order.Order
    :members:

Utils
#####
.. automodule:: acme_broker.util
    :members:
