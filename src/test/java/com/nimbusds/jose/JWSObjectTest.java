package com.nimbusds.jose;


import junit.framework.TestCase;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWS object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-01-15
 */
public class JWSObjectTest extends TestCase {


	public void testBase64URLConstructor()
		throws Exception {

		JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");

		JWSObject jws = new JWSObject(firstPart, secondPart, thirdPart);

		assertEquals(firstPart, jws.getHeader().toBase64URL());
		assertEquals(secondPart, jws.getPayload().toBase64URL());
		assertEquals(thirdPart, jws.getSignature());

		assertEquals(firstPart.toString() + ".abc.def", jws.serialize());
		assertEquals(firstPart.toString() + ".abc.def", jws.getParsedString());

		assertEquals(JWSObject.State.SIGNED, jws.getState());
	}


	public void testSignAndSerialize()
		throws Exception {

		JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

		JWSObject jwsObject = new JWSObject(header, new Payload("Hello world!"));

		Base64URL signingInput = Base64URL.encode(jwsObject.getSigningInput());

		assertTrue(signingInput.equals(Base64URL.encode(jwsObject.getSigningInput())));

		jwsObject.sign(new MACSigner("12345678901234567890123456789012"));

		String output = jwsObject.serialize();

		assertEquals(output, jwsObject.serialize());
	}
}