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


import java.net.URI;
import java.security.KeyStore;
import java.util.*;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class OctetKeyPairTest extends TestCase {
	
	
	// Test parameters are from JWK spec
	private static final class EXAMPLE_OKP_ED25519 {
		
		
		public static final Curve CRV = Curve.Ed25519;
		
		
		public static final Base64URL X = new Base64URL("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
		
		
		public static final Base64URL D = new Base64URL("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
	}
	
	
	private static final class EXAMPLE_OKP_X448 {
		
		public static final Curve CRV = Curve.X448;
		
		
		public static final Base64URL X = new Base64URL("PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk");
	}
	

	public void testParseRFCPrivateKeyExample()
		throws Exception {
		
		String json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
			"\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"," +
			"\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
		
		OctetKeyPair okp = OctetKeyPair.parse(json);
		
		assertEquals(KeyType.OKP, okp.getKeyType());
		assertEquals(Curve.Ed25519, okp.getCurve());
		assertEquals(new Base64URL("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), okp.getX());
		assertEquals(new Base64URL("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"), okp.getD());
		
		assertTrue(okp.isPrivate());
		
		JWK pubJWK = okp.toPublicJWK();
		OctetKeyPair pubOKP = (OctetKeyPair)pubJWK;
		assertEquals(KeyType.OKP, pubOKP.getKeyType());
		assertEquals(Curve.Ed25519, pubOKP.getCurve());
		assertEquals(okp.getX(), pubOKP.getX());
		assertNull(pubOKP.getD());
		
		assertFalse(pubOKP.isPrivate());
	}
	
	
	public void testParseRFCPublicKeyExample()
		throws Exception {
		
		String json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
			"\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
		
		OctetKeyPair okp = OctetKeyPair.parse(json);
		
		assertEquals(KeyType.OKP, okp.getKeyType());
		assertEquals(Curve.Ed25519, okp.getCurve());
		assertEquals(new Base64URL("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), okp.getX());
		assertNull(okp.getD());
		
		assertFalse(okp.isPrivate());
	}
	
	
	public void testThumbprintRFCExample()
		throws Exception {
		
		String json = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
		
		OctetKeyPair okp = OctetKeyPair.parse(json);
		
		assertEquals(KeyType.OKP, okp.getKeyType());
		assertEquals(Curve.Ed25519, okp.getCurve());
		assertEquals(new Base64URL("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), okp.getX());
		assertNull(okp.getD());
		
		assertFalse(okp.isPrivate());
		
		assertEquals("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", okp.computeThumbprint().toString());
	}
	
	
	public void testKeySizes() {
		
		assertEquals(256, new OctetKeyPair.Builder(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X).build().size());
		assertEquals(448, new OctetKeyPair.Builder(EXAMPLE_OKP_X448.CRV, EXAMPLE_OKP_X448.X).build().size());
	}
	
	
	public void testSupportedCurvesConstant() {
		
		assertTrue(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.Ed25519));
		assertTrue(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.Ed448));
		assertTrue(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.X25519));
		assertTrue(OctetKeyPair.SUPPORTED_CURVES.contains(Curve.X448));
		assertEquals(4, OctetKeyPair.SUPPORTED_CURVES.size());
	}
	
	
	public void testPrivateConstructorAndSerialization()
		throws Exception {
		
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));
		Set<KeyOperation> ops = null;
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		OctetKeyPair key = new OctetKeyPair(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X, EXAMPLE_OKP_ED25519.D,
			KeyUse.SIGNATURE, ops, JWSAlgorithm.EdDSA, "1", x5u, x5t, x5t256, x5c, keyStore);
		
		assertTrue(key instanceof AssymetricJWK);
		assertTrue(key instanceof CurveBasedJWK);
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(keyStore, key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertEquals(EXAMPLE_OKP_ED25519.D, key.getD());
		
		assertTrue(key.isPrivate());
		
		JSONObject jsonObject = key.toJSONObject();
		assertEquals(Curve.Ed25519.getName(), jsonObject.get("crv"));
		assertEquals(EXAMPLE_OKP_ED25519.X.toString(), jsonObject.get("x"));
		assertEquals(EXAMPLE_OKP_ED25519.D.toString(), jsonObject.get("d"));
		
		String jwkString = jsonObject.toString();
		
		key = OctetKeyPair.parse(jwkString);
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertNull(key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertEquals(EXAMPLE_OKP_ED25519.D, key.getD());
		
		assertTrue(key.isPrivate());
		
		
		// Test conversion to public JWK
		
		key = key.toPublicJWK();
		
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertNull(key.getD());
		
		assertFalse(key.isPrivate());
	}
	
	
	public void testPublicConstructorAndSerialization()
		throws Exception {
		
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));
		Set<KeyOperation> ops = null;
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		OctetKeyPair key = new OctetKeyPair(EXAMPLE_OKP_ED25519.CRV, EXAMPLE_OKP_ED25519.X, 
			KeyUse.SIGNATURE, ops, JWSAlgorithm.EdDSA, "1", x5u, x5t, x5t256, x5c, keyStore);
		
		assertTrue(key instanceof AssymetricJWK);
		assertTrue(key instanceof CurveBasedJWK);
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(keyStore, key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertNull(key.getD());
		
		assertFalse(key.isPrivate());
		
		JSONObject jsonObject = key.toJSONObject();
		assertEquals(Curve.Ed25519.getName(), jsonObject.get("crv"));
		assertEquals(EXAMPLE_OKP_ED25519.X.toString(), jsonObject.get("x"));
		assertFalse(jsonObject.containsKey("d"));
		
		String jwkString = jsonObject.toString();
		
		key = OctetKeyPair.parse(jwkString);
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertNull(key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertNull(key.getD());
		
		assertFalse(key.isPrivate());
	}
	
	
	public void testBuilder()
		throws Exception {
		
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5tS256 = new Base64URL("ghi");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
			.d(EXAMPLE_OKP_ED25519.D)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)))
			.algorithm(JWSAlgorithm.EdDSA)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertSHA256Thumbprint(x5tS256)
			.x509CertChain(x5c)
			.keyStore(keyStore)
			.build();
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)), key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u, key.getX509CertURL());
		assertEquals(x5t, key.getX509CertThumbprint());
		assertEquals(x5tS256, key.getX509CertSHA256Thumbprint());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(keyStore, key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertEquals(EXAMPLE_OKP_ED25519.D, key.getD());
		
		assertTrue(key.isPrivate());
		
		
		String jwkString = key.toJSONObject().toString();
		
		key = OctetKeyPair.parse(jwkString);
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)), key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertNull(key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertEquals(EXAMPLE_OKP_ED25519.D, key.getD());
		
		assertTrue(key.isPrivate());
		
		
		// Test conversion to public JWK
		
		key = key.toPublicJWK();
		
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY)), key.getKeyOperations());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u, key.getX509CertURL());
		assertEquals(x5t, key.getX509CertThumbprint());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertNull(key.getD());
		
		assertFalse(key.isPrivate());
	}
	
	
	public void testCopyBuilder()
		throws Exception {
		
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5tS256 = new Base64URL("ghi");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
			.d(EXAMPLE_OKP_ED25519.D)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.EdDSA)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertSHA256Thumbprint(x5tS256)
			.x509CertChain(x5c)
			.keyStore(keyStore)
			.build();
		
		// Copy
		key = new OctetKeyPair.Builder(key).build();
		
		// Test getters
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertEquals(JWSAlgorithm.EdDSA, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u, key.getX509CertURL());
		assertEquals(x5t, key.getX509CertThumbprint());
		assertEquals(x5tS256, key.getX509CertSHA256Thumbprint());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(keyStore, key.getKeyStore());
		
		assertEquals(Curve.Ed25519, key.getCurve());
		assertEquals(EXAMPLE_OKP_ED25519.X, key.getX());
		assertEquals(EXAMPLE_OKP_ED25519.D, key.getD());
		
		assertTrue(key.isPrivate());
	}
	
	
	public void testKeyIDFromThumbprint()
		throws Exception {
		
		OctetKeyPair key = new OctetKeyPair.Builder(Curve.Ed25519, EXAMPLE_OKP_ED25519.X)
			.keyIDFromThumbprint()
			.build();
		
		assertEquals(key.computeThumbprint().toString(), key.getKeyID());
	}
	
	
	public void testRejectUnsupportedCurve() {
		
		for(Curve crv: new HashSet<>(Arrays.asList(Curve.P_256, Curve.P_384, Curve.P_521))) {
			
			// public OKP
			try {
				new OctetKeyPair(crv, EXAMPLE_OKP_ED25519.X, null, null, null, null, null, null, null, null, null);
				fail();
			} catch (IllegalArgumentException e) {
				assertEquals("Unknown / unsupported curve: " + crv , e.getMessage());
			}
			
			// public / private OKP
			try {
				new OctetKeyPair(crv, EXAMPLE_OKP_ED25519.X, EXAMPLE_OKP_ED25519.D, null, null, null, null, null, null, null, null, null);
				fail();
			} catch (IllegalArgumentException e) {
				assertEquals("Unknown / unsupported curve: " + crv , e.getMessage());
			}
			
			// builder
			try {
				new OctetKeyPair.Builder(crv, EXAMPLE_OKP_ED25519.X).build();
				fail();
			} catch (IllegalStateException e) {
				assertEquals("Unknown / unsupported curve: " + crv , e.getMessage());
				assertTrue(e.getCause() instanceof IllegalArgumentException);
			}
		}
	}
}
