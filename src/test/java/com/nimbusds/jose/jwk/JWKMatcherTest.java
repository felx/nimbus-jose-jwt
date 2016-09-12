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

package com.nimbusds.jose.jwk;


import java.security.SecureRandom;
import java.util.*;
import javax.crypto.KeyGenerator;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import junit.framework.TestCase;


/**
 * Tests the JWK matcher.
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-08-24
 */
public class JWKMatcherTest extends TestCase {


	public void testMinimalConstructor() {

		JWKMatcher matcher = new JWKMatcher(null, null, null, null, null, false, false, 0, 0, null);

		assertNull(matcher.getKeyTypes());
		assertNull(matcher.getKeyUses());
		assertNull(matcher.getKeyOperations());
		assertNull(matcher.getAlgorithms());
		assertNull(matcher.getKeyIDs());
		assertFalse(matcher.hasKeyUse());
		assertFalse(matcher.hasKeyID());
		assertFalse(matcher.isPrivateOnly());
		assertFalse(matcher.isPublicOnly());
		assertEquals(0, matcher.getMinKeySize());
		assertEquals(0, matcher.getMinSize());
		assertEquals(0, matcher.getMaxKeySize());
		assertEquals(0, matcher.getMaxSize());
		assertNull(matcher.getKeySizes());
		assertNull(matcher.getCurves());
	}
	
	
	public void testAllSetDeprecatedConstructor() {

		Set<KeyType> types = new HashSet<>();
		types.add(KeyType.RSA);

		Set<KeyUse> uses = new HashSet<>();
		uses.add(KeyUse.SIGNATURE);

		Set<KeyOperation> ops = new HashSet<>();
		ops.add(KeyOperation.SIGN);
		ops.add(KeyOperation.VERIFY);
		
		Set<Algorithm> algs = new HashSet<>();
		algs.add(JWSAlgorithm.PS256);

		Set<String> ids = new HashSet<>();
		ids.add("1");

		JWKMatcher matcher = new JWKMatcher(types, uses, ops, algs, ids, true, true);

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertFalse(matcher.hasKeyUse());
		assertFalse(matcher.hasKeyID());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
		assertEquals(0, matcher.getMinKeySize());
		assertEquals(0, matcher.getMinSize());
		assertEquals(0, matcher.getMaxKeySize());
		assertEquals(0, matcher.getMaxSize());
		assertNull(matcher.getKeySizes());
		assertNull(matcher.getCurves());
	}
	
	
	public void testAllSet2ndDeprecatedConstructor() {

		Set<KeyType> types = new HashSet<>();
		types.add(KeyType.RSA);

		Set<KeyUse> uses = new HashSet<>();
		uses.add(KeyUse.SIGNATURE);

		Set<KeyOperation> ops = new HashSet<>();
		ops.add(KeyOperation.SIGN);
		ops.add(KeyOperation.VERIFY);
		
		Set<Algorithm> algs = new HashSet<>();
		algs.add(JWSAlgorithm.PS256);

		Set<String> ids = new HashSet<>();
		ids.add("1");

		JWKMatcher matcher = new JWKMatcher(types, uses, ops, algs, ids, true, true, 0, 0);

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertFalse(matcher.hasKeyUse());
		assertFalse(matcher.hasKeyID());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
		assertEquals(0, matcher.getMinKeySize());
		assertEquals(0, matcher.getMinSize());
		assertEquals(0, matcher.getMaxKeySize());
		assertEquals(0, matcher.getMaxSize());
		assertNull(matcher.getKeySizes());
		assertNull(matcher.getCurves());
	}


	public void testAllSet3rdDeprecatedConstructor() {

		Set<KeyType> types = new HashSet<>();
		types.add(KeyType.RSA);

		Set<KeyUse> uses = new HashSet<>();
		uses.add(KeyUse.SIGNATURE);

		Set<KeyOperation> ops = new HashSet<>();
		ops.add(KeyOperation.SIGN);
		ops.add(KeyOperation.VERIFY);

		Set<Algorithm> algs = new HashSet<>();
		algs.add(JWSAlgorithm.PS256);

		Set<String> ids = new HashSet<>();
		ids.add("1");
		
		Set<ECKey.Curve> curves = new HashSet<>();
		curves.add(ECKey.Curve.P_256);
		curves.add(ECKey.Curve.P_384);

		JWKMatcher matcher = new JWKMatcher(types, uses, ops, algs, ids, true, true, 128, 256, curves);

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertFalse(matcher.hasKeyUse());
		assertFalse(matcher.hasKeyID());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
		assertEquals(128, matcher.getMinKeySize());
		assertEquals(128, matcher.getMinSize());
		assertEquals(256, matcher.getMaxKeySize());
		assertEquals(256, matcher.getMaxSize());
		assertNull(matcher.getKeySizes());
		assertEquals(curves, matcher.getCurves());
	}


	public void testAllSet4thDeprecatedConstructor() {

		Set<KeyType> types = new HashSet<>();
		types.add(KeyType.RSA);

		Set<KeyUse> uses = new HashSet<>();
		uses.add(KeyUse.SIGNATURE);

		Set<KeyOperation> ops = new HashSet<>();
		ops.add(KeyOperation.SIGN);
		ops.add(KeyOperation.VERIFY);

		Set<Algorithm> algs = new HashSet<>();
		algs.add(JWSAlgorithm.PS256);

		Set<String> ids = new HashSet<>();
		ids.add("1");
		
		Set<Integer> sizes = new HashSet<>(Arrays.asList(128, 256));
		
		Set<ECKey.Curve> curves = new HashSet<>();
		curves.add(ECKey.Curve.P_256);
		curves.add(ECKey.Curve.P_384);

		JWKMatcher matcher = new JWKMatcher(types, uses, ops, algs, ids, true, true, 128, 256, sizes, curves);

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertFalse(matcher.hasKeyUse());
		assertFalse(matcher.hasKeyID());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
		assertEquals(128, matcher.getMinKeySize());
		assertEquals(128, matcher.getMinSize());
		assertEquals(256, matcher.getMaxKeySize());
		assertEquals(256, matcher.getMaxSize());
		assertTrue(matcher.getKeySizes().contains(128));
		assertTrue(matcher.getKeySizes().contains(256));
		assertEquals(2, matcher.getKeySizes().size());
		assertEquals(curves, matcher.getCurves());
	}


	public void testAllSetConstructor() {

		Set<KeyType> types = new HashSet<>();
		types.add(KeyType.RSA);

		Set<KeyUse> uses = new HashSet<>();
		uses.add(KeyUse.SIGNATURE);

		Set<KeyOperation> ops = new HashSet<>();
		ops.add(KeyOperation.SIGN);
		ops.add(KeyOperation.VERIFY);

		Set<Algorithm> algs = new HashSet<>();
		algs.add(JWSAlgorithm.PS256);

		Set<String> ids = new HashSet<>();
		ids.add("1");
		
		Set<Integer> sizes = new HashSet<>(Arrays.asList(128, 256));
		
		Set<ECKey.Curve> curves = new HashSet<>();
		curves.add(ECKey.Curve.P_256);
		curves.add(ECKey.Curve.P_384);

		JWKMatcher matcher = new JWKMatcher(types, uses, ops, algs, ids, true, true, true, true, 128, 256, sizes, curves);

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertTrue(matcher.hasKeyUse());
		assertTrue(matcher.hasKeyID());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
		assertEquals(128, matcher.getMinKeySize());
		assertEquals(128, matcher.getMinSize());
		assertEquals(256, matcher.getMaxKeySize());
		assertEquals(256, matcher.getMaxSize());
		assertTrue(matcher.getKeySizes().contains(128));
		assertTrue(matcher.getKeySizes().contains(256));
		assertEquals(2, matcher.getKeySizes().size());
		assertEquals(curves, matcher.getCurves());
	}
	
	
	public void testBuilderWithSets() {

		Set<KeyType> types = new HashSet<>();
		types.add(KeyType.RSA);

		Set<KeyUse> uses = new HashSet<>();
		uses.add(KeyUse.SIGNATURE);

		Set<KeyOperation> ops = new HashSet<>();
		ops.add(KeyOperation.SIGN);
		ops.add(KeyOperation.VERIFY);

		Set<Algorithm> algs = new HashSet<>();
		algs.add(JWSAlgorithm.PS256);

		Set<String> ids = new HashSet<>();
		ids.add("1");
		
		Set<Integer> sizes = new HashSet<>(Arrays.asList(128, 256));
		
		Set<ECKey.Curve> curves = new HashSet<>();
		curves.add(ECKey.Curve.P_256);
		curves.add(ECKey.Curve.P_384);
		
		JWKMatcher matcher = new JWKMatcher.Builder()
			.keyTypes(types)
			.keyUses(uses)
			.keyOperations(ops)
			.algorithms(algs)
			.keyIDs(ids)
			.hasKeyUse(true)
			.hasKeyID(true)
			.privateOnly(true)
			.publicOnly(true)
			.keySizes(sizes)
			.curves(curves)
			.build();

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertTrue(matcher.hasKeyUse());
		assertTrue(matcher.hasKeyID());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
		assertEquals(0, matcher.getMinKeySize());
		assertEquals(0, matcher.getMaxKeySize());
		assertEquals(sizes, matcher.getKeySizes());
		assertEquals(curves, matcher.getCurves());
	}
	
	
	public void testBuilderWithVarArgs() {

		JWKMatcher matcher = new JWKMatcher.Builder()
			.keyTypes(KeyType.EC, KeyType.RSA, null)
			.keyUses(KeyUse.SIGNATURE, null)
			.keyOperations(KeyOperation.SIGN, null)
			.algorithms(JWSAlgorithm.RS256, JWSAlgorithm.PS256)
			.keyIDs("1", "2", "3", null)
			.privateOnly(true)
			.publicOnly(true)
			.keySizes(128, 256)
			.curves(ECKey.Curve.P_256, null)
			.build();

		Set<KeyType> types = matcher.getKeyTypes();
		assertTrue(types.containsAll(Arrays.asList(KeyType.EC, KeyType.RSA, null)));
		assertEquals(3, types.size());

		Set<KeyUse> uses = matcher.getKeyUses();
		assertTrue(uses.containsAll(Arrays.asList(KeyUse.SIGNATURE, null)));
		assertEquals(2, uses.size());

		Set<KeyOperation> ops = matcher.getKeyOperations();
		assertTrue(ops.containsAll(Arrays.asList(KeyOperation.SIGN, null)));
		assertEquals(2, ops.size());

		Set<Algorithm> algs = matcher.getAlgorithms();
		assertTrue(algs.containsAll(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.PS256)));
		assertEquals(2, algs.size());

		Set<String> ids = matcher.getKeyIDs();
		assertTrue(ids.containsAll(Arrays.asList("1", "2", "3", null)));
		assertEquals(4, ids.size());
		
		assertFalse(matcher.hasKeyUse()); // skipped
		assertFalse(matcher.hasKeyID()); // skipped

		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());

		assertEquals(0, matcher.getMinKeySize());
		assertEquals(0, matcher.getMaxKeySize());
		
		assertTrue(matcher.getKeySizes().contains(128));
		assertTrue(matcher.getKeySizes().contains(256));
		assertEquals(2, matcher.getKeySizes().size());
		
		Set<ECKey.Curve> curves = matcher.getCurves();
		assertTrue(curves.containsAll(Arrays.asList(ECKey.Curve.P_256, null)));
		assertEquals(2, curves.size());
	}


	public void testDefaultBuilderPrivatePublicPolicy() {

		JWKMatcher matcher = new JWKMatcher.Builder().build();

		assertFalse(matcher.isPrivateOnly());
		assertFalse(matcher.isPublicOnly());
	}


	public void testMatchType() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyType(KeyType.RSA).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
		
		assertEquals("kty=RSA", matcher.toString());
	}


	public void testMatchTwoTypes() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyTypes(KeyType.RSA, KeyType.EC).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").build()));
		assertTrue(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
		
		assertEquals("kty=[RSA, EC]", matcher.toString());
	}


	public void testMatchUse() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyUse(KeyUse.ENCRYPTION).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.ENCRYPTION).build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
		
		assertEquals("use=enc", matcher.toString());
	}


	public void testMatchUseNotSpecifiedOrSignature() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyUses(KeyUse.SIGNATURE, null).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.SIGNATURE).build()));
		assertTrue(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3").keyUse(KeyUse.ENCRYPTION).build()));
		
		assertEquals("use=[sig, null]", matcher.toString());
	}


	public void testMatchOperation() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyOperation(KeyOperation.DECRYPT).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Collections.singletonList(KeyOperation.DECRYPT))).build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
		
		assertEquals("key_ops=decrypt", matcher.toString());
	}


	public void testMatchOperations() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyOperations(new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY))).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY))).build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
		
		assertEquals("key_ops=[sign, verify]", matcher.toString());
	}


	public void testMatchOperationsNotSpecifiedOrSign() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyOperations(KeyOperation.SIGN, null).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Collections.singletonList(KeyOperation.SIGN))).build()));

		assertTrue(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));

		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3")
			.keyOperations(new HashSet<>(Collections.singletonList(KeyOperation.ENCRYPT))).build()));
		
		assertEquals("key_ops=[sign, null]", matcher.toString());
	}


	public void testMatchAlgorithm() {

		JWKMatcher matcher = new JWKMatcher.Builder().algorithm(JWSAlgorithm.RS256).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertFalse(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.PS256).build()));
		
		assertEquals("alg=RS256", matcher.toString());
	}


	public void testMatchID() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyID("1").build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertFalse(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build()));
		
		assertEquals("kid=1", matcher.toString());
	}


	public void testMatchAnyID() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyID(null).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build()));
		
		assertEquals("", matcher.toString());
	}


	public void testMatchPrivateOnly() {

		JWKMatcher matcher = new JWKMatcher.Builder().privateOnly(true).build();

		assertFalse(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertTrue(matcher.matches(new OctetSequenceKey.Builder(new Base64URL("k")).build()));
		
		assertEquals("private_only=true", matcher.toString());
	}


	public void testMatchPublicOnly() {

		JWKMatcher matcher = new JWKMatcher.Builder().publicOnly(true).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertFalse(matcher.matches(new OctetSequenceKey.Builder(new Base64URL("k")).build()));
		
		assertEquals("public_only=true", matcher.toString());
	}


	public void testMatchComplex() {

		JWKMatcher matcher = new JWKMatcher.Builder()
			.keyType(KeyType.RSA)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.keyID("1")
			.publicOnly(true)
			.build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build()));
		assertFalse(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build()));
		
		assertEquals("kty=RSA use=sig alg=RS256 kid=1 public_only=true", matcher.toString());
	}


	public void testKeyTooShort() {

		byte[] keyMaterial = new byte[ByteUtils.byteLength(128 - 8)];
		new SecureRandom().nextBytes(keyMaterial);
		OctetSequenceKey jwk = new OctetSequenceKey.Builder(keyMaterial).build();
		assertFalse(new JWKMatcher.Builder().minKeySize(128).build().matches(jwk));
	}


	public void testMinSizeOk() {

		byte[] keyMaterial = new byte[ByteUtils.byteLength(128)];
		new SecureRandom().nextBytes(keyMaterial);
		OctetSequenceKey jwk = new OctetSequenceKey.Builder(keyMaterial).build();
		assertTrue(new JWKMatcher.Builder().minKeySize(128).build().matches(jwk));
	}


	public void testKeyTooLong() {

		byte[] keyMaterial = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(keyMaterial);
		OctetSequenceKey jwk = new OctetSequenceKey.Builder(keyMaterial).build();
		assertFalse(new JWKMatcher.Builder().maxKeySize(128).build().matches(jwk));
	}


	public void testMaxSizeOk() {

		byte[] keyMaterial = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(keyMaterial);
		OctetSequenceKey jwk = new OctetSequenceKey.Builder(keyMaterial).build();
		assertTrue(new JWKMatcher.Builder().maxKeySize(256).build().matches(jwk));
	}


	public void testKeySizeMatchesAcceptableRange() {

		byte[] keyMaterial = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(keyMaterial);
		OctetSequenceKey jwk = new OctetSequenceKey.Builder(keyMaterial).build();
		assertTrue(new JWKMatcher.Builder().minKeySize(128).maxKeySize(512).build().matches(jwk));
	}
	
	
	public void testMatchCurve_P256()
		throws Exception {
		
		String json = "{\"kty\":\"EC\"," +
			"\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"," +
			"\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"," +
			"\"crv\":\"P-256\"}";
		
		ECKey ecKey = ECKey.parse(json);
		
		JWKMatcher m = new JWKMatcher.Builder()
			.keyType(KeyType.EC)
			.curve(ECKey.Curve.P_256)
			.build();
		
		assertTrue(m.matches(ecKey));
		
		m = new JWKMatcher.Builder()
			.curve(ECKey.Curve.P_256)
			.build();
		
		assertTrue(m.matches(ecKey));
	}
	
	
	public void testNoMatchCurve_P384()
		throws Exception {
		
		String json = "{\"kty\":\"EC\"," +
			"\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"," +
			"\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"," +
			"\"crv\":\"P-256\"}";
		
		ECKey ecKey = ECKey.parse(json);
		
		JWKMatcher m = new JWKMatcher.Builder()
			.keyType(KeyType.EC)
			.curve(ECKey.Curve.P_384)
			.build();
		
		assertFalse(m.matches(ecKey));
	}
	
	
	public void testNoMatchCurve_otherKeyType()
		throws Exception {
		
		String json = "{" +
			"\"kty\":\"RSA\"," +
			"\"kid\":\"frodo.baggins@hobbiton.example\"," +
			"\"use\":\"enc\"," +
			"\"n\":\"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
			"HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
			"6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
			"NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
			"R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
			"pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
			"VotGlvMQ\"," +
			"\"e\":\"AQAB\"," +
			"\"d\":\"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
			"bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
			"5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
			"Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
			"1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
			"miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
			"pzj85bQQ\"," +
			"\"p\":\"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE" +
			"oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH" +
			"7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ" +
			"2VFmU\"," +
			"\"q\":\"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V" +
			"F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb" +
			"9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8" +
			"d6Et0\"," +
			"\"dp\":\"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH" +
			"QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV" +
			"RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf" +
			"lo0rYU\"," +
			"\"dq\":\"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb" +
			"pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A" +
			"CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14" +
			"TkXlHE\"," +
			"\"qi\":\"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ" +
			"lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7" +
			"Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx" +
			"2bQ_mM\"" +
			"}";
		
		RSAKey jwk = RSAKey.parse(json);
		
		JWKMatcher m = new JWKMatcher.Builder()
			.curve(ECKey.Curve.P_256)
			.build();
		
		assertFalse(m.matches(jwk));
		
		assertEquals("crv=P-256", m.toString());
	}
	
	
	public void testMatchKeySizes()
		throws Exception {
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		JWK jwk1 = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("1").build();
		
		keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(192);
		JWK jwk2 = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("2").build();
		
		keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		JWK jwk3 = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("3").build();
		
		JWKMatcher matcher = new JWKMatcher.Builder()
			.keySizes(128, 256)
			.build();
		
		assertTrue(matcher.matches(jwk1));
		assertFalse(matcher.matches(jwk2));
		assertTrue(matcher.matches(jwk3));
		
		assertEquals("size=[128, 256]", matcher.toString());
	}
	
	
	public void testMatchHasKeyUse()
		throws Exception {
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		JWK jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).build();
		
		JWKMatcher matcher = new JWKMatcher.Builder().hasKeyUse(false).build();
		
		assertTrue(matcher.matches(jwk));
		
		matcher = new JWKMatcher.Builder().hasKeyUse(true).build();
		
		assertFalse(matcher.matches(jwk));
		
		jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).keyUse(KeyUse.ENCRYPTION).build();
		
		assertTrue(matcher.matches(jwk));
		
		assertEquals("has_use=true", matcher.toString());
	}
	
	
	public void testMatchHasKeyID()
		throws Exception {
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		JWK jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).build();
		
		JWKMatcher matcher = new JWKMatcher.Builder().hasKeyID(false).build();
		
		assertTrue(matcher.matches(jwk));
		
		matcher = new JWKMatcher.Builder().hasKeyID(true).build();
		
		assertFalse(matcher.matches(jwk));
		
		jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("1").build();
		
		assertTrue(matcher.matches(jwk));
		
		assertEquals("has_id=true", matcher.toString());
	}
	
	
	public void testMatchHasKeyID_empty()
		throws Exception {
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		JWK jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("").build();
		
		JWKMatcher matcher = new JWKMatcher.Builder().hasKeyID(false).build();
		
		assertTrue(matcher.matches(jwk));
		
		matcher = new JWKMatcher.Builder().hasKeyID(true).build();
		
		assertFalse(matcher.matches(jwk));
		
		jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("1").build();
		
		assertTrue(matcher.matches(jwk));
	}
	
	
	public void testMatchHasKeyID_blank()
		throws Exception {
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		JWK jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("   ").build();
		
		JWKMatcher matcher = new JWKMatcher.Builder().hasKeyID(false).build();
		
		assertTrue(matcher.matches(jwk));
		
		matcher = new JWKMatcher.Builder().hasKeyID(true).build();
		
		assertFalse(matcher.matches(jwk));
		
		jwk = new OctetSequenceKey.Builder(keyGen.generateKey()).keyID("1").build();
		
		assertTrue(matcher.matches(jwk));
	}
}
