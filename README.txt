Nimbus JOSE + JWT

* The most popular Java library for signed and encrypted JSON Web Tokens (JWT)

* Complete JWS algorithm support

* RSA, AES key wrap and AES GCM encryption support with AES/CBC/HMAC and
  AES/GCM.

* Open source (Apache 2.0 licence)


Nimbus JOSE + JWT is an open source Java 7+ library which implements the
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

* HMAC integrity protection: HS256, HS384 and HS512

* RSASSA-PKCS1-V1_5 signatures: RS256, RS384 and RS512

* RSASSA-PSS signatures: PS256, PS384 and PS512

* EC signatures: ES256, ES384 and ES512

* Key encryption with RSAES-PKCS1-V1_5: RSA1_5

* Key encryption with RSAES OAEP: RSA-OAEP and RSA-OAEP-256

* Key encryption with AES key wrap: A128KW, A192KW and A256KW

* Key encryption with AES GCM: A128CGMKW, A192CGMKW and A256CGMKW

* Direct shared symmetric key encryption: dir

* Content encryption with AES_CBC_HMAC_SHA2: A128CBC-HS256, A192CBC-HS384,
  A256CBC-HS512, the deprecated A128CBC+HS256 and A256CBC+HS512 are also
  supported

* Content encryption with AES GCM: A128GCM, A192GCM and A256GCM

* JWE Compression with DEFLATE.


AES Key Wrap and ECDH-ES encryption is on the roadmap, you're welcome to
contribute in their development.


Related IETF drafts:

* [JWA] draft-ietf-jose-json-web-algorithms-36

* [JWS] draft-ietf-jose-json-web-signature-36

* [JWE] draft-ietf-jose-json-web-encryption-36

* [JWK] draft-ietf-jose-json-web-key-36

* [JWT] draft-ietf-oauth-json-web-token-30


System requirements and dependencies

The Nimbus JOSE+JWT library requires Java 7+ and has minimal dependencies.

* JSON Smart for highly efficient parsing and serialisation of JSON.

* JCIP for concurrency annotations.

* [optional] The BouncyCastle.org library, for ECDSA signing and verification,
  and for AES/CBC and AES/GCM encryption.


For Maven add:

<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>3.4</version>
</dependency>


To post bug reports and suggestions:

https://bitbucket.org/connect2id/nimbus-jose-jwt/issues


Follow us on Twitter:

https://twitter.com/connect2id



[EOF]
