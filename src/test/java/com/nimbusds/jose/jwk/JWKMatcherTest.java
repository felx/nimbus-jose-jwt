package com.nimbusds.jose.jwk;


import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the JWK matcher.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-15
 */
public class JWKMatcherTest extends TestCase {


	public void testMinimalConstructor() {

		JWKMatcher matcher = new JWKMatcher(null, null, null, null, null, false, false);

		assertNull(matcher.getKeyTypes());
		assertNull(matcher.getKeyUses());
		assertNull(matcher.getKeyOperations());
		assertNull(matcher.getAlgorithms());
		assertNull(matcher.getKeyIDs());
		assertFalse(matcher.isPrivateOnly());
		assertFalse(matcher.isPublicOnly());
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

		JWKMatcher matcher = new JWKMatcher(types, uses, ops, algs, ids, true, true);

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
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
		
		JWKMatcher matcher = new JWKMatcher.Builder()
			.keyTypes(types)
			.keyUses(uses)
			.keyOperations(ops)
			.algorithms(algs)
			.keyIDs(ids)
			.privateOnly(true)
			.publicOnly(true)
			.build();

		assertEquals(types, matcher.getKeyTypes());
		assertEquals(uses, matcher.getKeyUses());
		assertEquals(ops, matcher.getKeyOperations());
		assertEquals(algs, matcher.getAlgorithms());
		assertEquals(ids, matcher.getKeyIDs());
		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
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

		assertTrue(matcher.isPrivateOnly());
		assertTrue(matcher.isPublicOnly());
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
	}


	public void testMatchTwoTypes() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyTypes(KeyType.RSA, KeyType.EC).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").build()));
		assertTrue(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
	}


	public void testMatchUse() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyUse(KeyUse.ENCRYPTION).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.ENCRYPTION).build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
	}


	public void testMatchUseNotSpecifiedOrSignature() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyUses(KeyUse.SIGNATURE, null).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.SIGNATURE).build()));
		assertTrue(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3").keyUse(KeyUse.ENCRYPTION).build()));
	}


	public void testMatchOperation() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyOperation(KeyOperation.DECRYPT).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Arrays.asList(KeyOperation.DECRYPT))).build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
	}


	public void testMatchOperations() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyOperations(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY))).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY))).build()));
		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));
	}


	public void testMatchOperationsNotSpecifiedOrSign() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyOperations(KeyOperation.SIGN, null).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Arrays.asList(KeyOperation.SIGN))).build()));

		assertTrue(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build()));

		assertFalse(matcher.matches(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3")
			.keyOperations(new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT))).build()));
	}


	public void testMatchAlgorithm() {

		JWKMatcher matcher = new JWKMatcher.Builder().algorithm(JWSAlgorithm.RS256).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertFalse(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.PS256).build()));
	}


	public void testMatchID() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyID("1").build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertFalse(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build()));
	}


	public void testMatchAnyID() {

		JWKMatcher matcher = new JWKMatcher.Builder().keyID(null).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build()));
	}


	public void testMatchPrivateOnly() {

		JWKMatcher matcher = new JWKMatcher.Builder().privateOnly(true).build();

		assertFalse(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertTrue(matcher.matches(new OctetSequenceKey.Builder(new Base64URL("k")).build()));
	}


	public void testMatchPublicOnly() {

		JWKMatcher matcher = new JWKMatcher.Builder().publicOnly(true).build();

		assertTrue(matcher.matches(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build()));
		assertFalse(matcher.matches(new OctetSequenceKey.Builder(new Base64URL("k")).build()));
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
	}
}
