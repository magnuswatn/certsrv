Examples
=========

**Generate a CSR with Cryptography and get a cert from an ADCS server:**

.. code:: python

    from certsrv import Certsrv

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

    ca_server = Certsrv("my-adcs-server.example.net", "myUser", "myPassword")
    pem_cert = ca_server.get_cert(pem_req, "WebServer")

    # Print the key and the cert
    pem_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
    )

    print("Cert:\n{}".format(pem_cert.decode()))
    print("Key:\n{}".format(pem_key.decode()))

**Generate a CSR with pyOpenSSL and get a cert from an ADCS server:**

.. code:: python

    import OpenSSL
    from certsrv import Certsrv

    # Generate a key
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate a CSR
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN="myserver.example.com"
    san = b"DNS: myserver.example.com"
    san_extension = OpenSSL.crypto.X509Extension(b"subjectAltName", False, san)
    req.add_extensions([san_extension])

    req.set_pubkey(key)
    req.sign(key, "sha256")

    # Get the cert from the ADCS server
    pem_req = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)

    ca_server = Certsrv("my-adcs-server.example.net", "myUser", "myPassword")
    pem_cert = ca_server.get_cert(pem_req, "WebServer")

    # Print the key and the cert
    pem_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

    print("Cert:\n{}".format(pem_cert.decode()))
    print("Key:\n{}".format(pem_key.decode()))


**Generate a CSR with pyOpenSSL and get a cert from an ADCS server with a template that requires admin approval:**

.. code:: python

    import time
    import OpenSSL
    import certsrv

    # Generate a key
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate a CSR
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN="myserver.example.com"
    san = b"DNS: myserver.example.com"
    san_extension = OpenSSL.crypto.X509Extension(b"subjectAltName", False, san)
    req.add_extensions([san_extension])

    req.set_pubkey(key)
    req.sign(key, "sha256")

    # Get the cert from the ADCS server
    ca_server = certsrv.Certsrv("my-adcs-server.example.net", "myUser", "myPassword")
    pem_req = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)

    try:
        pem_cert = ca_server.get_cert(pem_req, "WebServerManual")
    except certsrv.CertificatePendingException as error:
        print("The request needs to be approved by the CA admin."
              "The Request Id is {}. She has a minute to approve it...".format(error.req_id))
        time.sleep(60)
        pem_cert = ca_server.get_existing_cert(error.req_id)

    # Print the key and the cert
    pem_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

    print("Cert:\n{}".format(pem_cert.decode()))
    print("Key:\n{}".format(pem_key.decode()))
