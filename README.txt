Nimbus JOSE+JWT

README

Nimbus JOSE+JWT is a Java library that implements the Javascript Object Signing 
and Encryption (JOSE) spec suite and the closely related JSON Web Token (JWT) 
spec.

The library supports creating, querying, serialising and parsing of the 
following JOSE and JWT objects:
	
	* Plain (unsecured) JOSE objects.
	
	* JSON Web Signature (JWS) objects.
	
	* JSON Web Encryption (JWE) objects.
	
	* JSON Web Key (JWK) objects and JSON Web Key (JWK) Sets.
	
	* Plain, signed and encrypted JSON Web Tokens (JWTs).


The JOSE and JWT object representation is decoupled from crypto algorithm (JWA)
implementations through a set of nimble interfaces for signing, verifying, 
encrypting and decrypting the objects.

The library currently ships with a ready implementation of the following 
standard algorithms:

	* HMAC signatures with HS256, HS384 and HS512.
	
	* RSA signatures with RS256, RS384 and RS512.
	
	* EC signatures with ES256, ES384 and ES512.
	

Related IETF drafts:

	* [JWA] draft-ietf-jose-json-web-algorithms-06

	* [JWS] draft-ietf-jose-json-web-signature-06

	* [JWE] draft-ietf-jose-json-web-encryption-06

	* [JWK] draft-ietf-jose-json-web-key-06

	* [JWT] draft-ietf-oauth-json-web-token-04


Dependencies:

	* Apache Commons Codec for Base64 and Base64URL encoding and decoding.

	* JSON Smart for highly efficient parsing and serialisation of JSON. 

	* [optional] The BouncyCastle.org cryptography provider for Java, for 
	  ECDSA signing and verification.


Uses:

	* JWT bearer tokens in OAuth 2.0
	
	* OpenID Connect
	
	* XMPP


About us:

The principal maintainer of this library is Nimbus Directory Services 
[http://NimbusDS.com]. The initial code was based on JWS/JWE/JWT crypto classes
factored out of the OpenInfoCard project. A rewrite to fully decouple JOSE + JWT
object representation from crypto algorithm implementation led to the next major 
2.0 release in October 2012.

You're welcome to contribute crypto handlers for standard algorithms which have
not been implemented yet (most JWE algorithms).


Acknowledgements:

	* Axel Nennker and the guys behind OpenInfoCard.
	* Everyone on the JOSE IETF WG list.
	* CertiVox UK for supporting the development.
	* Ville Kurkinen for adding Maven POM support.


To post bug reports and suggestions: 

	https://bitbucket.org/nimbusds/nimbus-jose-jwt/issues


Follow us on Twitter: 
	
	https://twitter.com/NimbusDS

[EOF]
