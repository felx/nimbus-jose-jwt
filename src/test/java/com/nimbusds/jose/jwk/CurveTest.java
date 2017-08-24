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

package com.nimbusds.jose.jwk;


import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import com.nimbusds.jose.JWSAlgorithm;
import junit.framework.TestCase;


public class CurveTest extends TestCase {
	
	
	public void testStdCurves() {
		
		assertEquals("P-256", Curve.P_256.getName());
		assertEquals("secp256r1", Curve.P_256.getStdName());
		assertEquals("1.2.840.10045.3.1.7", Curve.P_256.getOID());
		
		assertEquals("P-384", Curve.P_384.getName());
		assertEquals("secp384r1", Curve.P_384.getStdName());
		assertEquals("1.3.132.0.34", Curve.P_384.getOID());
		
		assertEquals("P-521", Curve.P_521.getName());
		assertEquals("secp521r1", Curve.P_521.getStdName());
		assertEquals("1.3.132.0.35", Curve.P_521.getOID());
		
		assertEquals("Ed25519", Curve.Ed25519.getName());
		assertEquals("Ed25519", Curve.Ed25519.getStdName());
		assertNull(Curve.Ed25519.getOID());
		
		assertEquals("Ed448", Curve.Ed448.getName());
		assertEquals("Ed448", Curve.Ed448.getStdName());
		assertNull(Curve.Ed448.getOID());
		
		assertEquals("X25519", Curve.X25519.getName());
		assertEquals("X25519", Curve.X25519.getStdName());
		assertNull(Curve.X25519.getOID());
		
		assertEquals("X448", Curve.X448.getName());
		assertEquals("X448", Curve.X448.getStdName());
		assertNull(Curve.X448.getOID());
	}
	
	
	public void testUnsupportedCurveParams() {
		
		assertNull(new Curve("unsupported").toECParameterSpec());
	}
	
	
	public void testCurveParams() {
		
		ECParameterSpec ecParameterSpec;
		
		ecParameterSpec = Curve.P_256.toECParameterSpec();
		assertNotNull(ecParameterSpec);
		assertEquals(Curve.P_256, Curve.forECParameterSpec(ecParameterSpec));
		
		ecParameterSpec = Curve.P_384.toECParameterSpec();
		assertNotNull(ecParameterSpec);
		assertEquals(Curve.P_384, Curve.forECParameterSpec(ecParameterSpec));
		
		ecParameterSpec = Curve.P_521.toECParameterSpec();
		assertNotNull(ecParameterSpec);
		assertEquals(Curve.P_521, Curve.forECParameterSpec(ecParameterSpec));
		
		// No support
		assertNull(Curve.Ed25519.toECParameterSpec());
		assertNull(Curve.Ed448.toECParameterSpec());
		assertNull(Curve.X25519.toECParameterSpec());
		assertNull(Curve.X448.toECParameterSpec());
	}
	
	
	public void testCurveForStdName() {
		
		assertEquals(Curve.P_256, Curve.forStdName("secp256r1"));
		assertEquals(Curve.P_256, Curve.forStdName("prime256v1"));
		
		assertEquals(Curve.P_384, Curve.forStdName("secp384r1"));
		
		assertEquals(Curve.P_521, Curve.forStdName("secp521r1"));
		
		assertEquals(Curve.Ed25519, Curve.forStdName("Ed25519"));
		
		assertEquals(Curve.Ed448, Curve.forStdName("Ed448"));
		
		assertEquals(Curve.X25519, Curve.forStdName("X25519"));
		
		assertEquals(Curve.X448, Curve.forStdName("X448"));
	}
	
	
	public void testCurveForOID() {
		
		assertEquals(Curve.P_256, Curve.forOID(Curve.P_256.getOID()));
		assertEquals(Curve.P_384, Curve.forOID(Curve.P_384.getOID()));
		assertEquals(Curve.P_521, Curve.forOID(Curve.P_521.getOID()));
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/197/jwsalgorithm-should-have-knowledge-of-its
	public void testCurveForJWSAlgorithm() {
		
		assertEquals(Collections.singleton(Curve.P_256), Curve.forJWSAlgorithm(JWSAlgorithm.ES256));
		assertEquals(Collections.singleton(Curve.P_384), Curve.forJWSAlgorithm(JWSAlgorithm.ES384));
		assertEquals(Collections.singleton(Curve.P_521), Curve.forJWSAlgorithm(JWSAlgorithm.ES512));
		assertEquals(new HashSet<>(Arrays.asList(Curve.Ed25519, Curve.Ed448)), Curve.forJWSAlgorithm(JWSAlgorithm.EdDSA));
		
		// Not EC based
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.RS256));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.RS384));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.RS512));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.PS256));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.PS384));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.PS512));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.HS256));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.HS384));
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.HS512));
		
		// Unsupported
		assertNull(Curve.forJWSAlgorithm(JWSAlgorithm.parse("unsupported-jws-alg")));
		
		// null
		assertNull(Curve.forJWSAlgorithm(null));
	}
}
