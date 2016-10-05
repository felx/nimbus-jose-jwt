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


import java.text.ParseException;
import java.util.Set;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;


/**
 * Examples verification of draft-ietf-jose-jws-signing-input-options-02
 */
public class UnencodedJWSPayloadTest extends TestCase {

	// From http://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-09#section-4
	static final String octJWKString = "{" +
		"\"kty\":\"oct\"," +
		"\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"" +
		"}";


	static final OctetSequenceKey JWK;


	static {
		try {
			JWK = OctetSequenceKey.parse(octJWKString);
		} catch (ParseException e) {
			throw new RuntimeException(e.getMessage());
		}
	}


	public void testPayloadAsBase64URL() {

		assertEquals("$.02", new Base64URL("JC4wMg").decodeToString());
	}


	public void testControlJWS()
		throws Exception {

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("$.02"));
		jwsObject.sign(new MACSigner(JWK));
		String expected = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";
		assertEquals(expected, jwsObject.serialize());
	}


	public void testB64False()
		throws Exception {

		Base64URL headerB64 = new Base64URL("eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19");
		JWSHeader header = JWSHeader.parse(headerB64);
		assertEquals(JWSAlgorithm.HS256, header.getAlgorithm());
		assertFalse((Boolean) header.getCustomParam("b64"));
		Set<String> crit = header.getCriticalParams();
		assertTrue(crit.contains("b64"));
		assertEquals(1, crit.size());
		assertEquals(3, header.toJSONObject().size());

		JWSSigner signer = new MACSigner(JWK);

		byte[] headerBytes = (header.toBase64URL().toString() + '.').getBytes("UTF-8");
		byte[] payloadBytes = "$.02".getBytes("UTF-8");
		byte[] signingInput = new byte[headerBytes.length + payloadBytes.length];
		System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
		System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length, payloadBytes.length);

		Base64URL signature = signer.sign(header, signingInput);
		Base64URL expectedSignature = new Base64URL("A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY");
		assertEquals(expectedSignature, signature);
	}
}
