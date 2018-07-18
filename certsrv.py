"""
A Python client for the Microsoft AD Certificate Services web page.

https://github.com/magnuswatn/certsrv
"""
import re
import base64
import logging
import warnings
import requests

__version__ = "2.0.0"

logger = logging.getLogger(__name__)

TIMEOUT = 30

class RequestDeniedException(Exception):
    """Signifies that the request was denied by the ADCS server."""
    def __init__(self, message, response):
        Exception.__init__(self, message)
        self.response = response

class CouldNotRetrieveCertificateException(Exception):
    """Signifies that the certificate could not be retrieved."""
    def __init__(self, message, response):
        Exception.__init__(self, message)
        self.response = response

class CertificatePendingException(Exception):
    """Signifies that the request needs to be approved by a CA admin."""
    def __init__(self, req_id):
        Exception.__init__(self, 'Your certificate request has been received. '
                                 'However, you must wait for an administrator to issue the'
                                 'certificate you requested. Your Request Id is %s.' % req_id)
        self.req_id = req_id

class Certsrv(object):
    """
    Represents a Microsoft AD Certificate Services web server.

    Args:
        server: The FQDN to a server running the Certification Authority
                Web Enrollment role (must be listening on https)
        username: The username for authentication
        password: The password for authentication
        auth_method: The chosen authentication method. Either 'basic' (the default) or 'ntlm'
        cafile: A PEM file containing the CA certificates that should be trusted
        timeout: The timeout to use against the CA server, in seconds. The default is 30.
    """
    def __init__(self, server, username, password, auth_method="basic",
                 cafile=None, timeout=TIMEOUT):
        self.server = server
        self.timeout = timeout
        self.session = requests.Session()

        if cafile:
            self.session.verify = cafile

        if auth_method == "ntlm":
            from requests_ntlm import HttpNtlmAuth
            self.session.auth = HttpNtlmAuth(username, password)
        else:
            self.session.auth = (username, password)

        # We need certsrv to think we are a browser, or otherwise the Content-Type of the
        # retrieved certificate will be wrong (for some reason)
        self.session.headers = {
            'User-agent': 'Mozilla/5.0 certsrv (https://github.com/magnuswatn/certsrv)'
        }


    def _get(self, url, **kwargs):
        response = self.session.get(url, timeout=self.timeout, **kwargs)

        logger.debug(
            "Sent %s request to %s, with headers:\n%s\n\nand body:\n%s",
            response.request.method,
            response.request.url,
            "\n".join(
                ["{0}: {1}".format(k, v) for k, v in response.request.headers.items()]
            ),
            response.request.body,
        )

        try:
            debug_content = response.content.decode()
        except UnicodeDecodeError:
            debug_content = base64.b64encode(response.content)

        logger.debug(
            "Recieved response:\nHTTP %s\n%s\n\n%s",
            response.status_code,
            "\n".join(["{0}: {1}".format(k, v) for k, v in response.headers.items()]),
            debug_content,
        )

        response.raise_for_status()

        return response

    def get_cert(self, csr, template, encoding="b64"):
        """
        Gets a certificate from the server.

        Args:
            csr: The certificate request to submit
            template: The certificate template the cert should be issued from
            encoding: The desired encoding for the returned certificate.
                      Possible values are "bin" for binary and "b64" for Base64 (PEM)

        Returns:
            The issued certificate

        Raises:
            RequestDeniedException: If the request was denied by the ADCS server
            CertificatePendingException: If the request needs to be approved by a CA admin
            CouldNotRetrieveCertificateException: If something went wrong while fetching the cert
        """
        data = {
            "Mode": "newreq",
            "CertRequest": csr,
            "CertAttrib": "CertificateTemplate:%s" % template,
            "UserAgent": "certsrv (https://github.com/magnuswatn/certsrv)",
            "FriendlyType": "Saved-Request Certificate",
            "TargetStoreFlags": "0",
            "SaveCert": "yes"
        }

        url = "https://{}/certsrv/certfnsh.asp".format(self.server)

        response = self._get(url, data=data)

        # We need to parse the Request ID from the returning HTML page
        try:
            req_id = re.search(r"certnew.cer\?ReqID=(\d+)&", response.text).group(1)
        except AttributeError:
            # We didn't find any request ID in the response. It may need approval.
            if re.search(r"Certificate Pending", response.text):
                req_id = re.search(r"Your Request Id is (\d+).", response.text).group(1)
                raise CertificatePendingException(req_id)
            else:
                # Must have failed. Lets find the error message and raise a RequestDeniedException
                try:
                    error = re.search(
                        r'The disposition message is "([^"]+)',
                        response.text
                    ).group(1)
                except AttributeError:
                    error = "An unknown error occured"
                raise RequestDeniedException(error, response.text)

        return self.get_existing_cert(req_id, encoding)

    def get_existing_cert(self, req_id, encoding="b64"):
        """
        Gets a certificate that has already been created.

        Args:
            req_id: The request ID to retrieve
            encoding: The desired encoding for the returned certificate.
                    Possible values are "bin" for binary and "b64" for Base64 (PEM)

        Returns:
            The issued certificate

        Raises:
            CouldNotRetrieveCertificateException: If something went wrong while fetching the cert
        """

        cert_url = "https://{}/certsrv/certnew.cer".format(self.server)
        params = {"ReqID": req_id, "Enc": encoding}

        response = self._get(cert_url, params=params)

        if response.headers["Content-Type"] != "application/pkix-cert":
            # The response was not a cert. Something must have gone wrong
            try:
                error = re.search(
                    "Disposition message:[^\t]+\t\t([^\r\n]+)",
                    response.text
                ).group(1)

            except AttributeError:
                error = "An unknown error occured"
            raise CouldNotRetrieveCertificateException(error, response.text)
        else:
            return response.content

    def get_ca_cert(self, encoding="b64"):
        """
        Gets the (newest) CA certificate from a Microsoft AD Certificate Services web page.

        Args:
            encoding: The desired encoding for the returned certificate.
                    Possible values are "bin" for binary and "b64" for Base64 (PEM)

        Returns:
            The newest CA certificate from the server
        """
        url = "https://{}/certsrv/certcarc.asp".format(self.server)

        response = self._get(url)

        # We have to check how many renewals this server has had, so that we get the newest CA cert
        renewals = re.search(r"var nRenewals=(\d+);", response.text).group(1)

        cert_url = "https://{}/certsrv/certnew.cer".format(self.server)
        params = {"ReqID": "CACert", "Enc": encoding, "Renewal": renewals}

        response = self._get(cert_url, params=params)

        if response.headers["Content-Type"] != "application/pkix-cert":
            raise CouldNotRetrieveCertificateException("An unknown error occured", response.content)

        return response.content

    def get_chain(self, encoding="bin"):
        """
        Gets the chain from a Microsoft AD Certificate Services web page.

        Args:
            encoding: The desired encoding for the returned certificates.
                    Possible values are "bin" for binary and "b64" for Base64 (PEM)

        Returns:
            The CA chain from the server, in PKCS#7 format
        """
        url = "https://{}/certsrv/certcarc.asp".format(self.server)

        response = self._get(url)

        # We have to check how many renewals this server has had, so that we get the newest chain
        renewals = re.search(r'var nRenewals=(\d+);', response.text).group(1)

        chain_url = "https://{}/certsrv/certnew.p7b".format(self.server)
        params = {"ReqID": "CACert", "Renewal": renewals, "Enc": encoding}

        chain_response = self._get(chain_url, params=params)

        if chain_response.headers["Content-Type"] != "application/x-pkcs7-certificates":
            raise CouldNotRetrieveCertificateException(
                "An unknown error occured",
                chain_response.content,
            )

        return chain_response.content

    def check_credentials(self):
        """
        Checks the specified credentials against the specified ADCS server

        Returns:
            True if authentication succeeded, False if it failed.
        """
        url = "https://{}/certsrv/".format(self.server)

        try:
            self._get(url)
        except requests.exceptions.HTTPError as error:
            if error.response.status_code == 401:
                return False
            else:
                raise
        return True

def get_cert(server, csr, template, username, password, encoding='b64', **kwargs):
    """
    Gets a certificate from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
                Web Enrollment role (must be listening on https)
        csr: The certificate request to submit
        template: The certificate template the cert should be issued from
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificate.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)
        auth_method: The chosen authentication method. Either 'basic' (the default) or 'ntlm'
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The issued certificate

    Raises:
        RequestDeniedException: If the request was denied by the ADCS server
        CertificatePendingException: If the request needs to be approved by a CA admin
        CouldNotRetrieveCertificateException: If something went wrong while fetching the cert

    .. note:: This method is deprecated.

    """
    warnings.warn(
        "This function is deprecated. Use the method on the Certsrv class instead",
        DeprecationWarning
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_cert(csr, template, encoding)

def get_existing_cert(server, req_id, username, password, encoding='b64', **kwargs):
    """
    Gets a certificate that has already been created.

    Args:
        server: The FQDN to a server running the Certification Authority
                Web Enrollment role (must be listening on https)
        req_id: The request ID to retrieve
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificate.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)
        auth_method: The chosen authentication method. Either 'basic' (the default) or 'ntlm'
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The issued certificate

    Raises:
        CouldNotRetrieveCertificateException: If something went wrong while fetching the cert

    .. note:: This method is deprecated.
    """
    warnings.warn(
        "This function is deprecated. Use the method on the Certsrv class instead",
        DeprecationWarning
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_existing_cert(req_id, encoding)

def get_ca_cert(server, username, password, encoding='b64', **kwargs):
    """
    Gets the (newest) CA certificate from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificate.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)
        auth_method: The chosen authentication method. Either 'basic' (the default) or 'ntlm'
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The newest CA certificate from the server

    .. note:: This method is deprecated.
    """
    warnings.warn(
        "This function is deprecated. Use the method on the Certsrv class instead",
        DeprecationWarning
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_ca_cert(encoding)

def get_chain(server, username, password, encoding='bin', **kwargs):
    """
    Gets the chain from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificates.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)
        auth_method: The chosen authentication method. Either 'basic' (the default) or 'ntlm'
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The CA chain from the server, in PKCS#7 format

    .. note:: This method is deprecated.
    """
    warnings.warn(
        "This function is deprecated. Use the method on the Certsrv class instead",
        DeprecationWarning
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_chain(encoding)

def check_credentials(server, username, password, **kwargs):
    """
    Checks the specified credentials against the specified ADCS server

    Args:
        ca: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        auth_method: The chosen authentication method. Either 'basic' (the default) or 'ntlm'
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        True if authentication succeeded, False if it failed.

    .. note:: This method is deprecated.
    """
    warnings.warn(
        "This function is deprecated. Use the method on the Certsrv class instead",
        DeprecationWarning
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.check_credentials()
