Testing
-------

The tests are functional tests that must be run against an ADCS server. The framework used is `pytest <https://docs.pytest.org>`_.

ADCS setup
----------

The ADCS server must be domain joined, so that it has template support, and it must have two templates - one that requires manual approval, and one that don't.

The IIS server must be set up to accept both NTLM and basic auth.

Most of this setup can be achieved by using the test_setup_adcs.ps1 script:

1. Install a fresh Windows Server (e.g. from Azure).
2. Run the script.
   It will first set up ADDS (not for production use!) and reboot.
3. After the reboot, run the script once again.
   It will then set up ADCS and IIS with an Let's Encrypt certificate and basic auth enabled.
4. Then the manual approval template must be manually created:
   clone the WebServer template and tick the "CA certificate manager approval" box under the "Issuance Requirements" tab.
5. All done.

Running tests
-------------

Install the test requirements:

.. code:: bash

    $ pipenv install --dev


And run the tests:

.. code:: bash

    pipenv run py.test --adcs my.adcs.server --username MyUsername --password MyPassword --template TemplateThatDoesNotReqireApproval --manual-template TemplateThatRequiresApproval --cafile /path/to/cafile


They should all pass :-)
