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

package com.nimbusds.jose.crypto;


import com.nimbusds.jose.jwk.Curve;
import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests ES256 JWS signing and verification. Uses test vectors from JWS spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2018-08-23
 */
public class ECDSASpecVectorsTest extends TestCase {


	private final static byte[] x = { 
		(byte) 127, (byte) 205, (byte) 206, (byte)  39, 
		(byte) 112, (byte) 246, (byte) 196, (byte)  93, 
		(byte)  65, (byte) 131, (byte) 203, (byte) 238, 
		(byte) 111, (byte) 219, (byte)  75, (byte) 123, 
		(byte)  88, (byte)   7, (byte)  51, (byte)  53, 
		(byte) 123, (byte) 233, (byte) 239, (byte)  19, 
		(byte) 186, (byte) 207, (byte) 110, (byte)  60, 
		(byte) 123, (byte) 209, (byte)  84, (byte)  69 };


	private final static byte[] y = { 
		(byte) 199, (byte) 241, (byte)  68, (byte) 205, 
		(byte)  27, (byte) 189, (byte) 155, (byte) 126, 
		(byte) 135, (byte) 44,  (byte) 223, (byte) 237, 
		(byte) 185, (byte) 238, (byte) 185, (byte) 244, 
		(byte) 179, (byte) 105, (byte)  93, (byte) 110, 
		(byte) 169, (byte)  11, (byte)  36, (byte) 173, 
		(byte) 138, (byte)  70, (byte)  35, (byte)  40, 
		(byte) 133, (byte) 136, (byte) 229, (byte) 173 };


	private final static byte[] d = { 
		(byte) 142, (byte) 155, (byte)  16, (byte) 158, 
		(byte) 113, (byte) 144, (byte) 152, (byte) 191, 
		(byte) 152, (byte)   4, (byte) 135, (byte) 223, 
		(byte)  31, (byte)  93, (byte) 119, (byte) 233, 
		(byte) 203, (byte)  41, (byte)  96, (byte) 110, 
		(byte) 190, (byte) 210, (byte)  38, (byte)  59, 
		(byte)  95, (byte)  87, (byte) 194, (byte)  19, 
		(byte) 223, (byte) 132, (byte) 244, (byte) 178 };


	private final static ECKey EC_JWK = new ECKey.Builder(Curve.P_256,
		Base64URL.encode(x), Base64URL.encode(y)).
		d(Base64URL.encode(d)).
		build();


	private static final Base64URL b64header = new Base64URL("eyJhbGciOiJFUzI1NiJ9");


	private static final Payload payload = new Payload(new Base64URL("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"));


	private static final byte[] signable = ("eyJhbGciOiJFUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ").getBytes();


	private static final Base64URL b64sig = new Base64URL("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
			"pmWQxfKTUJqPP3-Kg6NU1Q");


	public void testInstanceAlgorithmSupport()
		throws Exception {

		ECDSASigner signer = new ECDSASigner(EC_JWK);

		assertEquals(1, signer.supportedJWSAlgorithms().size());
		assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.ES256));

		ECDSAVerifier verifier = new ECDSAVerifier(EC_JWK);

		assertEquals(1, verifier.supportedJWSAlgorithms().size());
		assertTrue(verifier.supportedJWSAlgorithms().contains(JWSAlgorithm.ES256));
	}



	public void testSignAndVerify()
		throws Exception {

		JWSHeader header = JWSHeader.parse(b64header);

		assertEquals("ES256 alg check", JWSAlgorithm.ES256, header.getAlgorithm());

		JWSObject jwsObject = new JWSObject(header, payload);

		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());


		ECDSASigner signer = new ECDSASigner(EC_JWK);

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());


		ECDSAVerifier verifier = new ECDSAVerifier(EC_JWK);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Verified signature", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testSignWithReadyVector()
		throws Exception {

		// http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-05#section-3.4
		//
		// Note that ECDSA digital signature contains a value referred to as K,
		// which is a random number generated for each digital signature
		// instance.  This means that two ECDSA digital signatures using exactly
		// the same input parameters will output different signature values
		// because their K values will be different.  A consequence of this is
		// that one cannot verify an ECDSA signature by recomputing the signature
		// and comparing the results.
	}


	public void testVerifyWithReadyVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(b64header);

		JWSVerifier verifier =  new ECDSAVerifier(EC_JWK);

		boolean verified = verifier.verify(header, signable, b64sig);

		assertTrue("Signature check", verified);
	}


	public void testParseAndVerify()
		throws Exception {

		String s = b64header.toString() + "." + payload.toBase64URL().toString() + "." + b64sig.toString();

		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		JWSVerifier verifier =  new ECDSAVerifier(EC_JWK);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Signature check", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}
}
