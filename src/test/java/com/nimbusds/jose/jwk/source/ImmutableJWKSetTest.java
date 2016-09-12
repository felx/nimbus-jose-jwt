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

package com.nimbusds.jose.jwk.source;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import com.nimbusds.jose.jwk.*;
import junit.framework.TestCase;


public class ImmutableJWKSetTest extends TestCase {
	

	public void testRun()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(2048);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey((RSAPrivateKey)keyPair.getPrivate())
			.keyID("1")
			.build();

		JWKSet jwkSet = new JWKSet(rsaJWK);

		ImmutableJWKSet immutableJWKSet = new ImmutableJWKSet(jwkSet);

		assertEquals(jwkSet, immutableJWKSet.getJWKSet());

		List<JWK> matches = immutableJWKSet.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);
		RSAKey m1 = (RSAKey)matches.get(0);
		assertEquals(rsaJWK.getModulus(), m1.getModulus());
		assertEquals(rsaJWK.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK.getPrivateExponent(), m1.getPrivateExponent());
		assertEquals(1, matches.size());
	}
}
