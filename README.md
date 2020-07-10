# HTTP Public Key Pinning - SPKI Fingerprint Generation using Python

This is an implementation of converting the a PEM certificate's Subject Public Key Info (SPKI) into a 
pin. 

**NOTE**: There are warnings against using public key pinning due to its risks:

* Ars Technica article: [*How to hurricane-proof a Web server* ](https://arstechnica.com/information-technology/2017/09/how-to-hurricane-proof-a-web-server/)
* SCOTT HELME: [*I'm giving up on HPKP*](https://scotthelme.co.uk/im-giving-up-on-hpkp/)
* Smashing Magazine: [*Be Afraid Of HTTP Public Key Pinning (HPKP)*](https://www.smashingmagazine.com/be-afraid-of-public-key-pinning/)

## Information on the structure

The pin directive (as indicated in the [IETF's RFC 7469 Sesction 2.1.1](https://tools.ietf.org/html/rfc7469#section-2.1.1)) is a shown in the diagram below where the *token* is the name of the hashing algorithm.
Currently only `SHA256` is supported.

![Summary of the Pin directive diagram: pin-token = value](images/hpkp_pin_directive.png)

A full example being: `pin-sha256="8RoC2kEF47SCVwX8Er+UBJ44pDfDZY6Ku5mm9bSXT3o=";`. However, the Python
code in this repository outputs the PKP in the format: `sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`. 
This is consistent with how pins are accepte in other languages/frameworks, such as OkHttp3 
(see the `Add()` method for its [`CertificatePinner.Builder class`](https://square.github.io/okhttp/3.x/okhttp/okhttp3/CertificatePinner.Builder.html)) 

In [section 2.4 of the RFC](https://tools.ietf.org/html/rfc7469#section-2.4) the SPKI Fingerprint
is defined as:

> The output of a known cryptographic hash algorithm whose input is the DER-encoded ASN.1 
> representation of the Subject Public Key Info (SPKI) of an X.509 certificate.

A pin is defined as:

> The combination of the known algorithm identifier and the SPKI Fingerprint computed using that algorithm. 

## Notes

* To change the implementation to use M2Crypto and be able to install/run it on Windows, see:
    * https://stackoverflow.com/a/54046778/6288413
    * https://stackoverflow.com/a/25128855/6288413

## Resources

Here are some resources I used:

* https://www.pyopenssl.org/en/stable/api/crypto.html#x509-objects
* https://security.stackexchange.com/questions/84499/how-to-add-certificate-pinning-for-a-certain-domain-to-my-web-browser
* https://www.ssllabs.com/ssltest/analyze.html?d=appmattus.com
* https://cryptography.io/en/latest/x509/reference/
* https://stackoverflow.com/questions/7689941/how-can-i-retrieve-the-tls-ssl-peer-certificate-of-a-remote-host-using-python
* https://stackoverflow.com/a/36186060/6288413
* https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey