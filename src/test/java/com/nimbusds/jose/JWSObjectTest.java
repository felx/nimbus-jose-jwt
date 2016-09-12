/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

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