Testing
-------

The tests are functional tests that must be run against an ADCS server. The framework used is `pytest <https://docs.pytest.org>`_.

ADCS setup
----------

The IIS server must be set up to accept both NTLM and basic auth. The ADCS server must have two templates - one that requires manual approval, and one that don't.

Running tests
-------------

Install the test requirements:

.. code:: bash

    $ pip install -r requirements.test.txt


And run the tests:

.. code:: bash

    py.test --adcs my.adcs.server --username MyUsername --password MyPassword --template TemplateThatDoesNotReqireApproval --manual-template TemplateThatRequiresApproval --cafile /path/to/cafile


They should all pass :-)
