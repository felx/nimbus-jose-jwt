package com.nimbusds.jose;


import junit.framework.TestCase;

import com.nimbusds.jose.util.Base64URL;


/**
 * Tests JWS object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-07-15)
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
}