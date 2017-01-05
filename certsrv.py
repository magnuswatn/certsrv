"""
A Python client for the Microsoft AD Certificate Services web page.
"""
import re
import urllib
import urllib2

class RequestDeniedException(Exception):
    """Signifies that the request was denied by the ADCS server."""
    pass

def get_cert(server, csr, template, username, password, encoding='b64'):
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

    Returns:
        The issued certificate

    Raises:
        RequestDeniedException: If the requests was denied by the ADCS server
    """
    basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
    headers = {
        'Content-type': 'application/x-www-form-urlencoded',
        'Authorization':'Basic %s' % basicauth_header
    }
    data = {
        'Mode': 'newreq',
        'CertRequest': csr,
        'CertAttrib': 'CertificateTemplate:%s' % template,
        'UserAgent': 'Python',
        'FriendlyType':'Saved-Request Certificate',
        'TargetStoreFlags':'0',
        'SaveCert':'yes'
    }
    data_encoded = urllib.urlencode(data)
    url = 'https://%s/certsrv/certfnsh.asp' % server
    req = urllib2.Request(url, data_encoded, headers)
    response = urllib2.urlopen(req)
    response_page = response.read()
    # We need to parse the Request ID from the returning HTML page
    try:
        req_id = re.search(r'certnew.cer\?ReqID=(\d+)&', response_page).group(1)
    except AttributeError:
        # We didn't find any request ID in the response. The request must have failed.
        # Lets find the error message and raise an exception
        try:
            error = re.search(r'The disposition message is "([^"]+)', response_page).group(1)
        except AttributeError:
            error = 'An unknown error occured'
        raise RequestDeniedException(error)

    cert_url = 'https://%s/certsrv/certnew.cer?ReqID=%s&Enc=%s' % (server, req_id, encoding)
    cert_req = urllib2.Request(cert_url)
    cert_req.add_header("Authorization", "Basic %s" % basicauth_header)
    cert = urllib2.urlopen(cert_req).read()
    return cert

def get_ca_cert(server, username, password, encoding='b64'):
    """
    Gets the (newest) CA certificate from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificate.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)

    Returns:
        The newest CA certificate from the server
    """
    basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
    url = 'https://%s/certsrv/certcarc.asp' % server
    req = urllib2.Request(url)
    req.add_header("Authorization", "Basic %s" % basicauth_header)
    response = urllib2.urlopen(req)
    response_page = response.read()
    # We have to check how many renewals this server has had, so that we get the newest CA cert
    renewals = re.search(r'var nRenewals=(\d+);', response_page).group(1)
    cert_url = 'https://%s/certsrv/certnew.cer?ReqID=CACert&Renewal=%s&Enc=%s' % (server,
                                                                                  renewals,
                                                                                  encoding)
    cert_req = urllib2.Request(cert_url)
    cert_req.add_header("Authorization", "Basic %s" % basicauth_header)
    cert = urllib2.urlopen(cert_req).read()
    return cert

def get_chain(server, username, password, encoding='bin'):
    """
    Gets the chain from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication
        encoding: The desired encoding for the returned certificates.
                  Possible values are "bin" for binary and "b64" for Base64 (PEM)

    Returns:
        The CA chain from the server, in PKCS#7 format
    """
    basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
    url = 'https://%s/certsrv/certcarc.asp' % server
    req = urllib2.Request(url)
    req.add_header("Authorization", "Basic %s" % basicauth_header)

    response = urllib2.urlopen(req)
    response_page = response.read()
    # We have to check how many renewals this server has had, so that we get the newest chain
    renewals = re.search(r'var nRenewals=(\d+);', response_page).group(1)
    chain_url = 'https://%s/certsrv/certnew.p7b?ReqID=CACert&Renewal=%s&Enc=%s' % (server,
                                                                                   renewals,
                                                                                   encoding)
    chain_req = urllib2.Request(chain_url)
    chain_req.add_header("Authorization", "Basic %s" % basicauth_header)
    chain = urllib2.urlopen(chain_req).read()
    return chain

def check_credentials(server, username, password):
    """
    Checks the specified credentials against the specified ADCS server

    Args:
        ca: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https)
        username: The username for authentication
        pasword: The password for authentication

    Returns:
        True if authentication succeeded, False if it failed.
    """
    basicauth_header = urllib2.base64.b64encode('%s:%s' % (username, password))
    url = 'https://%s/certsrv/' % server
    req = urllib2.Request(url)
    req.add_header("Authorization", "Basic %s" % basicauth_header)
    try:
        urllib2.urlopen(req)
    except urllib2.HTTPError as error:
        if error.code == 401:
            return False
        else:
            raise
    else:
        return True
