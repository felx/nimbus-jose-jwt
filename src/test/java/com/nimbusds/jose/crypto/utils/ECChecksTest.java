/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto.utils;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import com.nimbusds.jose.jwk.Curve;
import junit.framework.TestCase;


public class ECChecksTest extends TestCase {
	
	
	private static ECPrivateKey generateECPrivateKey(final Curve curve)
		throws Exception {
		
		final ECParameterSpec ecParameterSpec = curve.toECParameterSpec();
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		KeyPair keyPair = generator.generateKeyPair();
		
		return (ECPrivateKey) keyPair.getPrivate();
	}
	
	
	private static ECPublicKey generateECPublicKey(final Curve curve)
		throws Exception {
		
		final ECParameterSpec ecParameterSpec = curve.toECParameterSpec();
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(ecParameterSpec);
		KeyPair keyPair = generator.generateKeyPair();
		
		return (ECPublicKey) keyPair.getPublic();
	}
	
	
	public void testCurveCheckOk()
		throws Exception {
		
		ECPublicKey ephemeralPublicKey = generateECPublicKey(Curve.P_256);
		ECPrivateKey privateKey = generateECPrivateKey(Curve.P_256);
		assertTrue(ECChecks.isPointOnCurve(ephemeralPublicKey, privateKey));
	}
}
