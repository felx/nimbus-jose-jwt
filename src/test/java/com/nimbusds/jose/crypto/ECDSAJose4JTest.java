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


import junit.framework.TestCase;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.ECKey;


/**
 * Jose4j interop test.
 *
 * @version 2015-05-30
 */
public class ECDSAJose4JTest extends TestCase {


	private static final String EC_P521_JWK_JSON = "{"+
		"\"kty\":\"EC\","+
		"\"kid\":\"bilbo.baggins@hobbiton.example\","+
		"\"use\":\"sig\","+
		"\"crv\":\"P-521\","+
		"\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"+
		"A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\","+
		"\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"+
		"SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\","+
		"\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"+
		"KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\""+
		"}";


	public void testES512NimbusEncryptJose4jDecrypt()
		throws Exception {

		ECKey jwk = ECKey.parse(EC_P521_JWK_JSON);

		// Create JWS
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES512), new Payload("Hello world!"));
		jwsObject.sign(new ECDSASigner(jwk));
		String compactJWS = jwsObject.serialize();

		// Verify JWS
		JsonWebKey jwk2 = JsonWebKey.Factory.newJwk(EC_P521_JWK_JSON);
		JsonWebSignature jws = new JsonWebSignature();
		jws.setCompactSerialization(compactJWS);
		jws.setKey(jwk2.getKey());
		assertTrue(jws.verifySignature());
		assertEquals("Hello world!", jws.getPayload());
	}


	public void testES512Jose4jEncryptNimbusDecrypt()
		throws Exception {

		// Create JWS
		JsonWebKey jwk = JsonWebKey.Factory.newJwk(EC_P521_JWK_JSON);
		JsonWebSignature jws = new JsonWebSignature();
		jws.setHeader("alg", "ES512");
		jws.setPayload("Hello world!");
		// jws.setKey(jwk.getKey()); // fails, check with jose4j todo - post ticket to jose4j
		jws.setKey(ECKey.parse(EC_P521_JWK_JSON).toECPrivateKey());
		jws.sign();
		String compactJWS = jws.getCompactSerialization();

		// Verify JWS
		ECKey jwk2 = ECKey.parse(EC_P521_JWK_JSON);
		JWSObject jwsObject = JWSObject.parse(compactJWS);
		assertTrue(jwsObject.verify(new ECDSAVerifier(jwk2)));
		assertEquals("Hello world!", jwsObject.getPayload().toString());
	}
}
