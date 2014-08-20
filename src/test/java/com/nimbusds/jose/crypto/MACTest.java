package com.nimbusds.jose.crypto;


import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import junit.framework.TestCase;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests HMAC JWS signing and verification. Uses test vectors from JWS spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-10)
 */
public class MACTest extends TestCase {


	private static final byte[] sharedSecret = 

		{ (byte)   3, (byte)  35, (byte)  53, (byte)  75, (byte)  43, (byte)  15, (byte) 165, (byte) 188, 
		  (byte) 131, (byte) 126, (byte)   6, (byte) 101, (byte) 119, (byte) 123, (byte) 166, (byte) 143, 
		  (byte)  90, (byte) 179, (byte)  40, (byte) 230, (byte) 240, (byte)  84, (byte) 201, (byte)  40, 
		  (byte) 169, (byte)  15, (byte) 132, (byte) 178, (byte) 210, (byte)  80, (byte)  46, (byte) 191, 
		  (byte) 211, (byte) 251, (byte)  90, (byte) 146, (byte) 210, (byte)   6, (byte)  71, (byte) 239, 
		  (byte) 150, (byte) 138, (byte) 180, (byte) 195, (byte) 119, (byte)  98, (byte)  61, (byte)  34, 
		  (byte)  61, (byte)  46, (byte)  33, (byte) 114, (byte)   5, (byte)  46, (byte)  79, (byte)   8, 
		  (byte) 192, (byte) 205, (byte) 154, (byte) 245, (byte) 103, (byte) 208, (byte) 128, (byte) 163  };


	private static final Base64URL b64header = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");


	private static final Payload payload = new Payload(new Base64URL("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"));


	private static final byte[] signable = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ").getBytes();


	private static final Base64URL b64sig = new Base64URL("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");



	public void testSupportedAlgorithms() {

		MACSigner signer = new MACSigner(sharedSecret);

		assertEquals(3, signer.supportedAlgorithms().size());
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS256));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS384));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS512));

		MACVerifier verifier = new MACVerifier(sharedSecret);

		assertEquals(3, verifier.supportedAlgorithms().size());
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.HS256));
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.HS384));
		assertTrue(verifier.supportedAlgorithms().contains(JWSAlgorithm.HS512));
	}


	public void testGetAcceptedAlgorithms() {

		MACVerifier verifier = new MACVerifier(sharedSecret);

		assertEquals(3, verifier.getAcceptedAlgorithms().size());
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.HS256));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.HS384));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.HS512));
	}


	public void testSetAcceptedAlgorithms() {

		MACVerifier verifier = new MACVerifier(sharedSecret);

		try {
			verifier.setAcceptedAlgorithms(null);
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		try {
			verifier.setAcceptedAlgorithms(new HashSet<>(Arrays.asList(JWSAlgorithm.ES256)));
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		verifier.setAcceptedAlgorithms(new HashSet<>(Arrays.asList(JWSAlgorithm.HS256)));
		assertTrue(verifier.getAcceptedAlgorithms().contains(JWSAlgorithm.HS256));
		assertEquals(1, verifier.getAcceptedAlgorithms().size());
	}



	public void testSignAndVerify()
		throws Exception {

		JWSHeader header = JWSHeader.parse(b64header);

		assertEquals("HS256 alg check", JWSAlgorithm.HS256, header.getAlgorithm());
		assertEquals("JWT type check", new JOSEObjectType("JWT"), header.getType());

		JWSObject jwsObject = new JWSObject(header, payload);

		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());


		MACSigner signer = new MACSigner(sharedSecret);
		assertEquals("Shared secret check", sharedSecret, signer.getSharedSecret());

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());


		MACVerifier verifier = new MACVerifier(sharedSecret);
		assertEquals("Shared secret check", sharedSecret, verifier.getSharedSecret());

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Verified signature", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testSignAndVerifyWithRandomSecret()
		throws Exception {

		// Generate random 32-bit shared secret
		SecureRandom random = new SecureRandom();
		byte[] sharedSecret = new byte[32];
		random.nextBytes(sharedSecret);

		// Create HMAC signer
		JWSSigner signer = new MACSigner(sharedSecret);

		// Prepare JWS object with "Hello, world!" payload
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello, world!"));

		// Apply the HMAC
		jwsObject.sign(signer);

		assertTrue(jwsObject.getState().equals(JWSObject.State.SIGNED));

		// To serialize to compact form, produces something like
		// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
		String s = jwsObject.serialize();

		// To parse the JWS and verify it, e.g. on client-side
		jwsObject = JWSObject.parse(s);

		JWSVerifier verifier = new MACVerifier(sharedSecret);

		assertTrue(jwsObject.verify(verifier));

		assertEquals("Hello, world!", jwsObject.getPayload().toString());
	}


	public void testSignAndVerifyWithStringSecret()
		throws Exception {

		final String stringSecret = "3eae8196ad1b";

		JWSHeader header = new JWSHeader(JWSAlgorithm.HS512);

		assertEquals("HS512 alg check", JWSAlgorithm.HS512, header.getAlgorithm());

		JWSObject jwsObject = new JWSObject(header, payload);

		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());


		MACSigner signer = new MACSigner(stringSecret);
		assertEquals("Shared secret string check", stringSecret, signer.getSharedSecretString());

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());


		MACVerifier verifier = new MACVerifier(stringSecret);
		assertEquals("Shared secret string check", stringSecret, verifier.getSharedSecretString());

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Verified signature", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testSignWithReadyVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(b64header);

		JWSSigner signer = new MACSigner(sharedSecret);

		Base64URL b64sigComputed = signer.sign(header, signable);

		assertEquals("Signature check", b64sig, b64sigComputed);
	}


	public void testVerifyWithReadyVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(b64header);

		JWSVerifier verifier = new MACVerifier(sharedSecret);

		boolean verified = verifier.verify(header, signable, b64sig);

		assertTrue("Signature check", verified);
	}


	public void testParseAndVerify()
		throws Exception {

		String s = b64header.toString() + "." + payload.toBase64URL().toString() + "." + b64sig.toString();

		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		JWSVerifier verifier = new MACVerifier(sharedSecret);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Signature check", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testCookbookExample()
		throws Exception {

		// See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-3.4.3

		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
			"\"use\":\"sig\","+
			"\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);

		String jws = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW"+
			"VlZjMxNGJjNzAzNyJ9"+
			"."+
			"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH"+
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk"+
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm"+
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"+
			"."+
			"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

		JWSObject jwsObject = JWSObject.parse(jws);

		assertEquals(JWSAlgorithm.HS256, jwsObject.getHeader().getAlgorithm());
		assertEquals("018c0ae5-4d9b-471b-bfd6-eef314bc7037", jwsObject.getHeader().getKeyID());

		JWSVerifier verifier = new MACVerifier(jwk.toByteArray());

		assertTrue(jwsObject.verify(verifier));

		assertEquals("SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4", jwsObject.getPayload().toBase64URL().toString());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		final String stringSecret = "3eae8196ad1b";

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		JWSObject jwsObject = new JWSObject(header, payload);

		MACSigner signer = new MACSigner(stringSecret);

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		MACVerifier verifier = new MACVerifier(stringSecret);
		verifier.getIgnoredCriticalHeaderParameters().add("exp");

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Verified signature", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		final String stringSecret = "3eae8196ad1b";

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		JWSObject jwsObject = new JWSObject(header, payload);

		MACSigner signer = new MACSigner(stringSecret);

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		MACVerifier verifier = new MACVerifier(stringSecret);

		boolean verified = jwsObject.verify(verifier);

		assertFalse("Verified signature", verified);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());
	}
}
