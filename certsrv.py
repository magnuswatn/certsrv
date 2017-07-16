"""
A Python client for the Microsoft AD Certificate Services web page.

https://github.com/magnuswatn/certsrv
"""
import re
import urllib
import urllib2

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

def get_cert(server, csr, template, username, password, encoding='b64', cafile=None):
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
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The issued certificate

    Raises:
        RequestDeniedException: If the request was denied by the ADCS server
        CertificatePendingException: If the request needs to be approved by a CA admin
        CouldNotRetrieveCertificateException: If something went wrong while fetching the cert
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 certsrv (https://github.com/magnuswatn/certsrv)',
        'Content-type': 'application/x-www-form-urlencoded',
        'Authorization':'Basic %s' % urllib2.base64.b64encode('%s:%s' % (username, password))
    }
    data = {
        'Mode': 'newreq',
        'CertRequest': csr,
        'CertAttrib': 'CertificateTemplate:%s' % template,
        'UserAgent': 'certsrv (https://github.com/magnuswatn/certsrv)',
        'FriendlyType':'Saved-Request Certificate',
        'TargetStoreFlags':'0',
        'SaveCert':'yes'
    }
    data_encoded = urllib.urlencode(data)
    url = 'https://%s/certsrv/certfnsh.asp' % server
    req = urllib2.Request(url, data_encoded, headers)
    if cafile:
        response = urllib2.urlopen(req, cafile=cafile)
    else:
        response = urllib2.urlopen(req)
    response_page = response.read()
    # We need to parse the Request ID from the returning HTML page
    try:
        req_id = re.search(r'certnew.cer\?ReqID=(\d+)&', response_page).group(1)
    except AttributeError:
        # We didn't find any request ID in the response. It may need approval.
        if re.search(r'Certificate Pending', response_page):
            req_id = re.search(r'Your Request Id is (\d+).', response_page).group(1)
            raise CertificatePendingException(req_id)
        else:
            # Must have failed. Lets find the error message and raise a RequestDeniedException
            try:
                error = re.search(r'The disposition message is "([^"]+)', response_page).group(1)
            except AttributeError:
                error = 'An unknown error occured'
            raise RequestDeniedException(error, response_page)
    return get_existing_cert(server, req_id, username, password, encoding, cafile)

def get_existing_cert(server, req_id, username, password, encoding='b64', cafile=None):
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
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The issued certificate

    Raises:
        CouldNotRetrieveCertificateException: If something went wrong while fetching the cert
    """
    headers = {
        # We need certsrv to think we are a browser, or otherwise the Content-Type will be wrong
        'User-Agent': 'Mozilla/5.0 certsrv (https://github.com/magnuswatn/certsrv)',
        'Authorization':'Basic %s' % urllib2.base64.b64encode('%s:%s' % (username, password))
    }

    cert_url = 'https://%s/certsrv/certnew.cer?ReqID=%s&Enc=%s' % (server, req_id, encoding)
    cert_req = urllib2.Request(cert_url, headers=headers)

    if cafile:
        response = urllib2.urlopen(cert_req, cafile=cafile)
    else:
        response = urllib2.urlopen(cert_req)

    response_content = response.read()
    if response.headers.type != 'application/pkix-cert':
        # The response was not a cert. Something must have gone wrong
        try:
            error = re.search('Disposition message:[^\t]+\t\t([^\r\n]+)', response_content).group(1)
        except AttributeError:
            error = 'An unknown error occured'
        raise CouldNotRetrieveCertificateException(error, response_content)
    else:
        return response_content

def get_ca_cert(server, username, password, encoding='b64', cafile=None):
    """
    Gets the (newest) CA certificate from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificate.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The newest CA certificate from the server
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 certsrv (https://github.com/magnuswatn/certsrv)',
        'Authorization':'Basic %s' % urllib2.base64.b64encode('%s:%s' % (username, password))
    }
    url = 'https://%s/certsrv/certcarc.asp' % server
    req = urllib2.Request(url, headers=headers)

    if cafile:
        response = urllib2.urlopen(req, cafile=cafile)
    else:
        response = urllib2.urlopen(req)

    response_page = response.read()
    # We have to check how many renewals this server has had, so that we get the newest CA cert
    renewals = re.search(r'var nRenewals=(\d+);', response_page).group(1)
    cert_url = 'https://%s/certsrv/certnew.cer?ReqID=CACert&Renewal=%s&Enc=%s' % (server,
                                                                                  renewals,
                                                                                  encoding)
    cert_req = urllib2.Request(cert_url, headers=headers)
    if cafile:
        cert = urllib2.urlopen(cert_req, cafile=cafile).read()
    else:
        cert = urllib2.urlopen(cert_req).read()

    return cert

def get_chain(server, username, password, encoding='bin', cafile=None):
    """
    Gets the chain from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificates.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        The CA chain from the server, in PKCS#7 format
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 certsrv (https://github.com/magnuswatn/certsrv)',
        'Authorization':'Basic %s' % urllib2.base64.b64encode('%s:%s' % (username, password))
    }
    url = 'https://%s/certsrv/certcarc.asp' % server
    req = urllib2.Request(url, headers=headers)

    if cafile:
        response = urllib2.urlopen(req, cafile=cafile)
    else:
        response = urllib2.urlopen(req)

    response_page = response.read()
    # We have to check how many renewals this server has had, so that we get the newest chain
    renewals = re.search(r'var nRenewals=(\d+);', response_page).group(1)
    chain_url = 'https://%s/certsrv/certnew.p7b?ReqID=CACert&Renewal=%s&Enc=%s' % (server,
                                                                                   renewals,
                                                                                   encoding)
    chain_req = urllib2.Request(chain_url, headers=headers)
    if cafile:
        chain = urllib2.urlopen(chain_req, cafile=cafile).read()
    else:
        chain = urllib2.urlopen(chain_req).read()
    return chain

def check_credentials(server, username, password, cafile=None):
    """
    Checks the specified credentials against the specified ADCS server

    Args:
        ca: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        cafile: A PEM file containing the CA certificates that should be trusted

    Returns:
        True if authentication succeeded, False if it failed.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 certsrv (https://github.com/magnuswatn/certsrv)',
        'Authorization':'Basic %s' % urllib2.base64.b64encode('%s:%s' % (username, password))
    }
    url = 'https://%s/certsrv/' % server
    req = urllib2.Request(url, headers=headers)
    try:
        if cafile:
            urllib2.urlopen(req, cafile=cafile)
        else:
            urllib2.urlopen(req)
    except urllib2.HTTPError as error:
        if error.code == 401:
            return False
        else:
            raise
    else:
        return True
