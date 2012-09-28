Nimbus JOSE+JWT

README

Nimbus JOSE+JWT is a comprehensive Java implementation of the Javascript Object 
Signing and Encryption (JOSE) spec suite and the closely related JSON Web Token 
(JWT) spec. 

The library supports creating, querying, serialising and parsing of the 
following JOSE and JWT objects:
	
	* Plain (unsecured) JOSE objects.
	
	* JSON Web Signature (JWS) objects.
	
	* JSON Web Encryption (JWE) objects.
	
	* JSON Web Key (JWK) objects and JSON Web Key (JWK) Sets.
	
	* Plain, signed and encrypted JSON Web Tokens (JWTs).


The JOSE and JWT object representation is completely decoupled from JSON Web 
Algorithm (JWA) implementations through a set of simple interfaces for signing,
validating, encrypting and decrypting the objects.

The library currently ships a ready implementation of the following standard 
algorithms:

	* HMAC signatures with HS256, HS384 and HS512.
	
	* RSA signatures with RS256, RS384 and RS512.
	
	* EC signatures with ES256, ES384 and ES512.
	

Related IETF drafts:

	* [JWA] draft-ietf-jose-json-web-algorithms-05

	* [JWS] draft-ietf-jose-json-web-signature-05

	* [JWE] draft-ietf-jose-json-web-encryption-05

	* [JWK] draft-ietf-jose-json-web-key-05

	* [JWT] draft-ietf-oauth-json-web-token-03


Dependencies:

	* Apache Commons Codec for Base64 and Base64URL encoding and decoding.

	* JSON Smart for highly efficient parsing and serialisation of JSON. 

	* [optional] The BouncyCastle.org cryptography provider for Java, for 
	  ECDSA signing and validation.

[EOF]
