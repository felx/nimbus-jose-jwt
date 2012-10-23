package com.nimbusds.jose.crypto;


import junit.framework.TestCase;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSValidator;
import com.nimbusds.jose.Payload;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests HS256 JWS signing and verfication. Uses test vectors from JWS spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
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
	
	
	private static final byte[] signable = new String("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
	                                                  "." +
							  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
							  "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ").getBytes();
	
	
	private static final Base64URL b64sig = new Base64URL("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
	
	
	
	public void testSignAndValidate()
		throws Exception {
	
		JWSHeader header = JWSHeader.parse(b64header);
		
		assertEquals("HS256 alg check", JWSAlgorithm.HS256, header.getAlgorithm());
		assertEquals("JWT type check", new JOSEObjectType("JWT"), header.getType());
		
		JWSObject jwsObject = new JWSObject(header, payload);
		
		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());
		
		
		MACSigner signer = new MACSigner(sharedSecret);
		assertEquals("Shared secret check", sharedSecret, signer.getSharedSecret());
		assertEquals(3, signer.supportedAlgorithms().size());
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS256));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS384));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS512));
		
		jwsObject.sign(signer);
		
		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());
		
		
		MACValidator validator = new MACValidator(sharedSecret);
		assertEquals("Shared secret check", sharedSecret, validator.getSharedSecret());
		assertEquals(3, signer.supportedAlgorithms().size());
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS256));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS384));
		assertTrue(signer.supportedAlgorithms().contains(JWSAlgorithm.HS512));
		
		boolean valid = jwsObject.validate(validator);
		
		assertTrue("Valid signature check", valid);
		
		assertEquals("State check", JWSObject.State.VALIDATED, jwsObject.getState());
	}
	
	
	public void testSignWithReadyVector()
		throws Exception {
	
		JWSHeader header = JWSHeader.parse(b64header);
		
		JWSSigner signer = new MACSigner(sharedSecret);
		
		Base64URL b64sigComputed = signer.sign(header, signable);
		
		assertEquals("Signature check", b64sig, b64sigComputed);
	}
	
	
	public void testValidateWithReadyVector()
		throws Exception {
	
		JWSHeader header = JWSHeader.parse(b64header);
		
		JWSValidator validator = new MACValidator(sharedSecret);
		
		boolean valid = validator.validate(header, signable, b64sig);
		
		assertTrue("Signature check", valid);
	}
	
	
	public void testParseAndValidate()
		throws Exception {
	
		String s = b64header.toString() + "." + payload.toBase64URL().toString() + "." + b64sig.toString();
		
		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());
		
		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());
		
		JWSValidator validator = new MACValidator(sharedSecret);
		
		boolean valid = jwsObject.validate(validator);
		
		assertTrue("Signature check", valid);
		
		assertEquals("State check", JWSObject.State.VALIDATED, jwsObject.getState());
	}
}
