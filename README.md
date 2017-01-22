certsrv
=====
A Python client for the Microsoft AD Certificate Services web page

It is quite normal to have an internal PKI based on the Microsoft AD Certificate Services, which work greate with Windows, but not so much on other OSes.
Users of other OSes must often manually create an CSR and then use the Certificate Services web page (certsrv) to get a certificate.
This is not ideal, as it is a manual and time consuming (and creating a csr with OpenSSL on the command line is confusing and complicated.)

This is a simple litle Python client for the certsrv page, so that Python programs can get certificates without manual operation.

## Prerequisites
The IIS server running the certsrv utility must have Basic Authentication enabled, and it MUST listen on HTTPS with a valid certificate.

It is known to work on Windows 2008R2 and 2012R2, but I'm sure it works on everything from 2003 to 2016.

## Disclaimer
The certsrv page is not an API, so this is obviously a little hackish and a little fragile. It will break if Microsoft does any changes to the certsrv application.

Luckily (or sadly?) they haven't changed much in the last 19 years...

## Warning
If you are using Red Hat, it is recommended to enable certificate validation (it is disabled by default!).

See: https://access.redhat.com/articles/2039753

## Example usage:
Generate a CSR with Cryptography and get a cert from an ADCS server
```python
import certsrv

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Generate a key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"myserver.example.com"),
])).add_extension(
    x509.SubjectAlternativeName([
        x509.DNSName(u"myserver.example.com"),
    ]),
    critical=False,
).sign(key, hashes.SHA256(), default_backend())

# Get the cert from the ADCS server
pem_req = csr.public_bytes(serialization.Encoding.PEM)
pem_cert = certsrv.get_cert('my-adcs-server.example.net', pem_req, 'WebServer', 'myUser', 'myPassword')

# Print the key and the cert
pem_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
)

print('Cert: %s' % pem_cert)
print('Key: %s' % pem_key)

```
Generate a CSR with pyOpenSSL and get a cert from an ADCS server
```python
import OpenSSL
import certsrv

# Generate a key
key = OpenSSL.crypto.PKey()
key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

# Generate a CSR
req = OpenSSL.crypto.X509Req()
req.get_subject().CN='myserver.example.com'
san = 'DNS: myserver.example.com'
san_extension = OpenSSL.crypto.X509Extension("subjectAltName", False, san)
req.add_extensions([san_extension])

req.set_pubkey(key)
req.sign(key, 'sha256')

# Get the cert from the ADCS server
pem_req = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
pem_cert = certsrv.get_cert('my-adcs-server.example.net', pem_req, 'WebServer', 'myUser', 'myPassword')

# Print the key and the cert
pem_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

print('Cert: %s' % pem_cert)
print('Key: %s' % pem_key)
```
