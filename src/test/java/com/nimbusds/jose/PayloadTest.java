package com.nimbusds.jose;


import junit.framework.TestCase;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;


/**
 * Tests the JOSE payload class.
 */
public class PayloadTest extends TestCase {


	public void testJWSObject()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
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
		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), "UTF-8"));
	}


	public void testJWSObjectFromString()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
		String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		Payload payload = new Payload(s);

		assertEquals(Payload.Origin.STRING, payload.getOrigin());
		assertEquals(JWSAlgorithm.HS256, payload.toJWSObject().getHeader().getAlgorithm());

		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), "UTF-8"));
	}


	public void testSignedJWT()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
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

		assertNotNull(payload.toJWSObject());

		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), "UTF-8"));
	}


	public void testSignedJWTFromString()
		throws Exception {

		// From http://tools.ietf.org/html/rfc7515#appendix-A.1
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

		assertNotNull(payload.toJWSObject());

		assertEquals(s, payload.toString());
		assertEquals(s, new String(payload.toBytes(), "UTF-8"));
	}


	public void testRejectUnsignedJWS() {

		try {
			new Payload(new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("test")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWS object must be signed", e.getMessage());
		}
	}


	public void testRejectUnsignedJWT() {

		try {
			new Payload(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet()));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWT must be signed", e.getMessage());
		}
	}


	public void testTransformer() {

		PayloadTransformer<Integer> transformer = new PayloadTransformer<Integer>() {
			@Override
			public Integer transform(final Payload payload) {

				return Integer.parseInt(payload.toString());
			}
		};

		Payload payload = new Payload("10");

		Integer out = payload.toType(transformer);

		assertEquals(new Integer(10), out);
	}
}
