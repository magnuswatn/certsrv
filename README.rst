certsrv
=======

.. image:: https://travis-ci.org/magnuswatn/certsrv.svg?branch=master
    :target: https://travis-ci.org/magnuswatn/certsrv

.. image:: https://codecov.io/gh/magnuswatn/certsrv/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/magnuswatn/certsrv

.. image:: https://badge.fury.io/py/certsrv.svg
    :target: https://pypi.org/project/certsrv/

It is quite normal to have an internal PKI based on the Microsoft AD
Certificate Services, which work great with Windows, but not so much on
other OSes. Users of other OSes must often manually create a CSR and
then use the Certificate Services web page (certsrv) to get a
certificate. This is not ideal, as it is a manual and time consuming
(and creating a csr with OpenSSL on the command line is confusing and
complicated.)

This is a simple litle Python client for the certsrv page, so that
Python programs can get certificates without manual operation.

Installation
------------

.. code-block:: bash

    $ pip install certsrv


Or, if you want NTLM support:

.. code-block:: bash

    $ pip install certsrv[ntlm]


Documentation
-------------

See `Documentation <https://certsrv.readthedocs.org>`_
