Nimbus JOSE+JWT


Nimbus JOSE+JWT is a Java library that implements the Javascript Object Signing
and Encryption (JOSE) spec suite and the closely related JSON Web Token (JWT) 
spec. Supported JOSE and JWT objects

The library supports creating, querying, serialising and parsing of the 
following JOSE and JWT objects:

	* Plain (unsecured) JOSE objects. 

	* JSON Web Signature (JWS) objects. 

	* JSON Web Encryption (JWE) objects. 

	* JSON Web Key (JWK) objects and JSON Web Key (JWK) Sets. 
 
	* Plain, signed and encrypted JSON Web Tokens (JWTs). 


The JOSE and JWT object representation is completely decoupled from JSON Web 
Algorithm (JWA) implementations through a set of simple interfaces for signing, 
verifying, encrypting and decrypting the objects. Developers can use the 
standard algorithm implementations or plug their own. All standard JWS and 
JWE RSA-based algorithms fully implemented

The library currently ships a ready implementation of the following standard 
algorithms:

	* HMAC signatures with HS256, HS384 and HS512. 

	* RSA signatures with RS256, RS384 and RS512. 

	* EC signatures with ES256, ES384 and ES512. 

	* RSAES-PKCS1-V1_5 encryption with A128CBC+HS256, A256CBC+HS512, 
	  A128GCM and A256GCM. 

	* RSAES OAEP encryption with A128CBC+HS256, A256CBC+HS512, A128GCM and 
	  A256GCM. 

	* JWE Compression with DEFLATE. 


AES Key Wray and ECDH-ES encryption is on the roadmap, you're welcome to 
contribute in their development. 


The library code comes with complete JavaDocs which can help you discover and 
make use of many special features. The JavaDocs are included in the download 
package. You can also browse them online.


http://nimbusds.com/files/jose-jwt/javadoc/


Related IETF drafts

	[JWA] draft-ietf-jose-json-web-algorithms-08 

	[JWS] draft-ietf-jose-json-web-signature-08 

	[JWE] draft-ietf-jose-json-web-encryption-08 

	[JWK] draft-ietf-jose-json-web-key-08 

	[JPSK] draft-jones-jose-json-private-and-symmetric-key-00 

	[JWT] draft-ietf-oauth-json-web-token-06 


Dependencies

The Nimbus JOSE+JWT library has minimal dependencies.

	* Apache Commons Codec for Base64 and Base64URL encoding and decoding. 

	* JSON Smart for highly efficient parsing and serialisation of JSON. 

	* [optional] The BouncyCastle.org cryptography provider for Java, for 
	  ECDSA signing and verification. 


Uses

	* JWT bearer tokens in OAuth 2.0 

	* OpenID Connect 

	* XMPP 


A generator for symmetric and RSA - based JSON Web Keys (JWKs), including a 
command-line utility, is available at

https://github.com/mitreid-connect/json-web-key-generator


About us

The principal maintainer of this library is Nimbus Directory Services 
[http://NimbusDS.com]. The initial code was based on JWS/JWE/JWT crypto classes 
factored out of the OpenInfoCard project. A rewrite to fully decouple JOSE + 
JWT object representation from crypto algorithm implementation led to the next 
major 2.0 release in October 2012.

The library has received numerous contributions and is now on the way to have 
all standard JWAs fully implemented. You're welcome to join us if you wish to 
help out with that.


To post bug reports and suggestions

	https://bitbucket.org/nimbusds/nimbus-jose-jwt/issues


Follow us on Twitter

	https://twitter.com/NimbusDS


[EOF]
