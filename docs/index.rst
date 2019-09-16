.. certsrv documentation master file, created by
   sphinx-quickstart on Mon Aug 14 21:05:23 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

certsrv
=======

*A Python client for the Microsoft AD Certificate Services web page*

It is quite normal to have an internal PKI based on the Microsoft AD
Certificate Services, which work great with Windows, but not so much on
other OSes. Users of other OSes must often manually create a CSR and
then use the Certificate Services web page (certsrv) to get a
certificate. This is not ideal, as it is a manual and time consuming
(and creating a csr with OpenSSL on the command line is confusing and
complicated.)

This is a simple litle Python client for the certsrv page, so that
Python programs can get certificates without manual operation.

Prerequisites
-------------

The IIS server must listen on HTTPS with a valid (trusted by the client)
certificate. It is recommended to enable basic auth on IIS, but NTLM is
also supported through the `requests_ntlm package <https://pypi.org/project/requests_ntlm/>`_.
You can also use kerberos through `requests-gssapi package <https://pypi.org/project/requests-gssapi/>`_.
for this to work, you'll need a valid TGT, which you can create using kinit

Disclaimer
----------

The certsrv page is not an API, so this is obviously a little hackish
and a little fragile. It will break if Microsoft does any changes to the
certsrv application.

Luckily (or sadly?) they haven’t changed much in the last 19 years…

Certsrv has been tested against Windows 2008R2, 2012R2 and 2016, but I’m sure it works
on everything from 2003 to 2019.

GitHub
------

`magnuswatn/certsrv <https://github.com/magnuswatn/certsrv>`_


Module Documentation
--------------------

.. toctree::
    :maxdepth: 2

    certsrv

.. toctree::
    :maxdepth: 2

    examples
