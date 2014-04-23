Nimbus JOSE + JWT

* The most popular Java library for signed and encrypted JSON Web Tokens (JWT)

* Full JWS algorithm and RSA encryption support

* Open source (Apache 2.0 licence)


Nimbus JOSE + JWT is an open source Java library which implements the
Javascript Object Signing and Encryption (JOSE) spec suite and the closely
related JSON Web Token (JWT) spec.


Supported JOSE and JWT objects

The library can create, examine, serialise and parse the following JOSE and JWT
objects (in compact format):

* Plain (unsecured) JOSE objects.

* JSON Web Signature (JWS) objects.

* JSON Web Encryption (JWE) objects.

* JSON Web Key (JWK) objects and JSON Web Key (JWK) Sets.

* Plain, signed and encrypted JSON Web Tokens (JWTs).



The library currently ships a ready implementation of the following standard
algorithms:

* HMAC integrity with HS256, HS384 and HS512.

* RSASSA-PKCS1-V1_5 signatures with RS256, RS384 and RS512.

* RSASSA-PSS signatures with PS256, PS384 and PS512.

* EC signatures with ES256, ES384 and ES512.

* RSAES-PKCS1-V1_5 encryption with A128CBC-HS256, A192CBC-HS384,
  A256CBC-HS512, A128GCM, A192GCM and A256GCM.

* RSAES OAEP encryption with A128CBC-HS256, A192CBC-HS384, A256CBC-HS512,
  A128GCM, A192GCM and A256GCM.

* Direct shared symmetric key encryption with A128CBC-HS256, A192CBC-HS384,
  A256CBC-HS512, A128GCM, A192GCM and A256GCM.

* JWE Compression with DEFLATE.


AES Key Wrap and ECDH-ES encryption is on the roadmap, you're welcome to
contribute in their development.


Related IETF drafts:

* [JWA] draft-ietf-jose-json-web-algorithms-25

* [JWS] draft-ietf-jose-json-web-signature-25

* [JWE] draft-ietf-jose-json-web-encryption-25

* [JWK] draft-ietf-jose-json-web-key-25

* [JWT] draft-ietf-oauth-json-web-token-19


Dependencies

The Nimbus JOSE+JWT library has minimal dependencies.

* JSON Smart for highly efficient parsing and serialisation of JSON.

* JCIP for concurrency annotations.

* [optional] The BouncyCastle.org cryptography provider for Java, for ECDSA
  signing and verification.


For Maven add:

<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>2.25</version>
</dependency>


To post bug reports and suggestions:

https://bitbucket.org/connect2id/nimbus-jose-jwt/issues


Follow us on Twitter:

https://twitter.com/connect2id



[EOF]
