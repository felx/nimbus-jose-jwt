package com.nimbusds.jose;


import junit.framework.TestCase;

import com.nimbusds.jwt.SignedJWT;


/**
 * Tests the JOSE payload class.
 */
public class PayloadTest extends TestCase {


	public void testJWSObject()
		throws Exception {

		// From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		JWSObject jwsObject = JWSObject.parse(s);

		Payload payload = new Payload(jwsObject);

		assertEquals(Payload.Origin.JWS_OBJECT, payload.getOrigin());
		assertEquals(jwsObject, payload.toJWSObject());
	}


	public void testJWSObjectFromString()
		throws Exception {

		// From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		Payload payload = new Payload(s);

		assertEquals(Payload.Origin.STRING, payload.getOrigin());
		assertEquals(JWSAlgorithm.HS256, payload.toJWSObject().getHeader().getAlgorithm());
	}


	public void testSignedJWT()
		throws Exception {

		// From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		SignedJWT signedJWT = SignedJWT.parse(s);

		Payload payload = new Payload(signedJWT);

		assertEquals(Payload.Origin.SIGNED_JWT, payload.getOrigin());
		assertEquals(signedJWT, payload.toSignedJWT());
	}


	public void testSignedJWTFromString()
		throws Exception {

		// From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		Payload payload = new Payload(s);

		assertEquals(Payload.Origin.STRING, payload.getOrigin());
		assertEquals(JWSAlgorithm.HS256, payload.toJWSObject().getHeader().getAlgorithm());
		assertEquals("joe", payload.toSignedJWT().getJWTClaimsSet().getIssuer());
	}
}
