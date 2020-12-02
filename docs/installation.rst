Installation
============

There are two supported installation methods: *bare-metal* and *docker*.

The bare-metal section focuses on deploying an :class:`~acme_broker.server.AcmeBroker` with a PostgreSQL
instance.
The docker section deploys a :class:`~acme_broker.server.AcmeCA`, also with a PostgreSQL database, behind an Nginx
reverse proxy.

In either case, the first step is to clone the repositoy:

.. code-block:: bash
   :substitutions:

   git clone |GIT_URL|
   cd acme-broker


Bare-metal
##########


Docker
######
