import pytest
import certsrv
import OpenSSL

from urllib2 import HTTPError

def create_csr():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN='certsrv-test-cert.no'
    san = 'DNS: certsrv-test-cert.no'
    san_extension = OpenSSL.crypto.X509Extension("subjectAltName", False, san)
    req.add_extensions([san_extension])
    req.set_pubkey(key)
    req.sign(key, 'sha256')
    return req

def check_cert_matches_csr_and_issuer(csr, cert, adcs, username, password):
    """
    Basic check that the cert matches the csr and the issuer
    Does not check the signature, so not for production use!
    """
    cert_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, cert.get_pubkey())
    csr_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, csr.get_pubkey())
    pem_issuer = certsrv.get_ca_cert(adcs, username, password)
    issuer = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_issuer)
    assert issuer.get_subject() == cert.get_issuer()
    assert cert_key == csr_key
    assert csr.get_subject() == cert.get_subject()




def test_get_cert_pem(opt_adcs, opt_username, opt_password, opt_template):
    csr = create_csr()
    pem_csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    pem_cert = certsrv.get_cert(opt_adcs, pem_csr, opt_template, opt_username, opt_password)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
    check_cert_matches_csr_and_issuer(csr, cert, opt_adcs, opt_username, opt_password)

def test_get_cert_der(opt_adcs, opt_username, opt_password, opt_template):
    csr = create_csr()
    pem_csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    der_cert = certsrv.get_cert(opt_adcs, pem_csr, opt_template, opt_username, opt_password, 'bin')
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)
    check_cert_matches_csr_and_issuer(csr, cert, opt_adcs, opt_username, opt_password)

def test_get_cert_invalid_csr(opt_adcs, opt_username, opt_password, opt_template):
    with pytest.raises(certsrv.RequestDeniedException) as excinfo:
        certsrv.get_cert(opt_adcs, 'NotACsr', opt_template, opt_username, opt_password)
    assert 'Error Parsing Request' in str(excinfo.value)

def test_get_cert_invalid_template(opt_adcs, opt_username, opt_password):
    csr = create_csr()
    pem_csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    with pytest.raises(certsrv.RequestDeniedException) as excinfo:
        certsrv.get_cert(opt_adcs, pem_csr, 'NotATemplate', opt_username, opt_password)
    assert 'The request was for a certificate template that is not supported' in str(excinfo.value)

def test_get_cert_that_needs_approval(opt_adcs, opt_username, opt_password, opt_mantemplate):
    csr = create_csr()
    pem_csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    with pytest.raises(certsrv.CertificatePendingException) as excinfo:
        certsrv.get_cert(opt_adcs, pem_csr, opt_mantemplate, opt_username, opt_password)
    assert 'you must wait for an administrator' in str(excinfo.value)

def test_get_non_existing_cert(opt_adcs, opt_username, opt_password):
    with pytest.raises(certsrv.CouldNotRetrieveCertificateException) as excinfo:
        certsrv.get_existing_cert(opt_adcs, -1, opt_username, opt_password)

def test_get_existing_cert_pem(opt_adcs, opt_username, opt_password):
    # Request number 1 should always exist, right?
    pem_cert = certsrv.get_existing_cert(opt_adcs, 1, opt_username, opt_password)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

def test_get_existing_cert_der(opt_adcs, opt_username, opt_password):
    # Request number 1 should always exist, right?
    der_cert = certsrv.get_existing_cert(opt_adcs, 1, opt_username, opt_password, 'bin')
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)

def test_check_credentials(opt_adcs, opt_username, opt_password):
    assert certsrv.check_credentials(opt_adcs, opt_username, opt_password)

def test_check_wrong_credentials(opt_adcs):
    assert certsrv.check_credentials(opt_adcs, 'wronguser', 'wrongpassword') == False

def test_get_ca_cert_pem(opt_adcs, opt_username, opt_password):
    pem_cert = certsrv.get_ca_cert(opt_adcs, opt_username, opt_password)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
    # If it is the current cert, it should be valid
    assert cert.has_expired() == False

def test_get_ca_cert_der(opt_adcs, opt_username, opt_password):
    bin_cert = certsrv.get_ca_cert(opt_adcs, opt_username, opt_password, 'bin')
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bin_cert)
    # If it is the current cert, it should be valid
    assert cert.has_expired() == False

def test_get_chain_pem(opt_adcs, opt_username, opt_password):
    pem_chain = certsrv.get_chain(opt_adcs, opt_username, opt_password, 'b64')
    # pyOpenSSL does not have an option to parse PKCS#7,
    # so we just check that it is the right encoding
    assert '-----BEGIN CERTIFICATE-----' in pem_chain

def test_get_chain_der(opt_adcs, opt_username, opt_password):
    der_chain = certsrv.get_chain(opt_adcs, opt_username, opt_password)
    # pyOpenSSL does not have an option to parse PKCS#7,
    # so we just check that it is the right encoding
    assert '-----BEGIN CERTIFICATE-----' not in der_chain
 
def test_get_cert_with_ntlm(opt_adcs, opt_username, opt_password, opt_template):
    csr = create_csr()
    pem_csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    pem_cert = certsrv.get_cert(opt_adcs, pem_csr, opt_template, opt_username, opt_password, auth_method='ntlm')
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
    check_cert_matches_csr_and_issuer(csr, cert, opt_adcs, opt_username, opt_password)

def test_get_existing_cert_with_ntlm(opt_adcs, opt_username, opt_password):
    # Request number 1 should always exist, right?
    pem_cert = certsrv.get_existing_cert(opt_adcs, 1, opt_username, opt_password)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

def test_check_credentials_with_ntlm(opt_adcs, opt_username, opt_password):
    assert certsrv.check_credentials(opt_adcs, opt_username, opt_password, auth_method='ntlm')

def test_check_wrong_credentials_with_ntlm(opt_adcs):
    assert certsrv.check_credentials(opt_adcs, 'wronguser', 'wrongpassword', auth_method='ntlm') == False

def test_get_ca_cert_with_ntlm(opt_adcs, opt_username, opt_password):
    pem_cert = certsrv.get_ca_cert(opt_adcs, opt_username, opt_password, auth_method='ntlm')
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
    # If it is the current cert, it should be valid
    assert cert.has_expired() == False

def test_get_chain_with_ntlm(opt_adcs, opt_username, opt_password):
    pem_chain = certsrv.get_chain(opt_adcs, opt_username, opt_password, 'b64', auth_method='ntlm')
    # pyOpenSSL does not have an option to parse PKCS#7,
    # so we just check that it is the right encoding
    assert '-----BEGIN CERTIFICATE-----' in pem_chain

def test_wrong_credentials(opt_adcs, opt_username, opt_password):
    with pytest.raises(HTTPError) as excinfo:
        certsrv.get_existing_cert(opt_adcs, -1, 'wronguser', 'wrongpassword')
    assert excinfo.value.msg == 'Unauthorized'

def test_wrong_credentials_with_ntlm(opt_adcs, opt_username, opt_password):
    # We should throw a HTTPError even when ntlm auth
    with pytest.raises(HTTPError) as excinfo:
        certsrv.get_existing_cert(opt_adcs, -1, 'wronguser', 'wrongpassword', auth_method='ntlm')
    assert excinfo.value.msg == 'Unauthorized'

