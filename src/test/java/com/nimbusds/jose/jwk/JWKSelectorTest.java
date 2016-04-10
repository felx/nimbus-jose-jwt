package com.nimbusds.jose.jwk;


import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.base64.Base64URL;


/**
 * Tests the JWK selector.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-15
 */
public class JWKSelectorTest extends TestCase {


	public void testConstructor() {

		JWKMatcher matcher = new JWKMatcher(null, null, null, null, null, false, false);

		JWKSelector selector = new JWKSelector(matcher);

		assertEquals(matcher, selector.getMatcher());
	}


	public void testSelectFromNullSet() {

		List<JWK> matches = new JWKSelector(new JWKMatcher.Builder().build()).select(null);

		assertTrue(matches.isEmpty());
	}


	public void testSelectFromEmptySet() {

		List<JWK> matches = new JWKSelector(new JWKMatcher.Builder().build()).select(new JWKSet());

		assertTrue(matches.isEmpty());
	}


	public void testSelectByType() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyType(KeyType.RSA).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals(KeyType.RSA, key1.getKeyType());
		assertEquals("1", key1.getKeyID());

		assertEquals(1, matches.size());
	}


	public void testSelectByTwoTypes() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyTypes(KeyType.RSA, KeyType.EC).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals(KeyType.RSA, key1.getKeyType());
		assertEquals("1", key1.getKeyID());

		ECKey key2 = (ECKey)matches.get(1);
		assertEquals(KeyType.EC, key2.getKeyType());
		assertEquals("2", key2.getKeyID());

		assertEquals(2, matches.size());
	}


	public void testSelectByUse() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyUse(KeyUse.ENCRYPTION).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.ENCRYPTION).build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals(KeyType.RSA, key1.getKeyType());
		assertEquals(KeyUse.ENCRYPTION, key1.getKeyUse());
		assertEquals("1", key1.getKeyID());

		assertEquals(1, matches.size());
	}


	public void testSelectByUseNotSpecifiedOrSignature() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyUses(KeyUse.SIGNATURE, null).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.SIGNATURE).build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3").keyUse(KeyUse.ENCRYPTION).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals(KeyType.RSA, key1.getKeyType());
		assertEquals(KeyUse.SIGNATURE, key1.getKeyUse());
		assertEquals("1", key1.getKeyID());

		ECKey key2 = (ECKey)matches.get(1);
		assertEquals(KeyType.EC, key2.getKeyType());
		assertEquals("2", key2.getKeyID());

		assertEquals(2, matches.size());
	}


	public void testSelectByOperations() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyOperations(KeyOperation.SIGN, KeyOperation.VERIFY).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY))).build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals(KeyType.RSA, key1.getKeyType());
		assertEquals("1", key1.getKeyID());

		assertEquals(1, matches.size());
	}


	public void testSelectByOperationsNotSpecifiedOrSign() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyOperations(KeyOperation.SIGN, null).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1")
			.keyOperations(new HashSet<>(Collections.singletonList(KeyOperation.SIGN))).build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());
		keyList.add(new ECKey.Builder(ECKey.Curve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3")
			.keyOperations(new HashSet<>(Collections.singletonList(KeyOperation.ENCRYPT))).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals(KeyType.RSA, key1.getKeyType());
		assertEquals("1", key1.getKeyID());

		ECKey key2 = (ECKey)matches.get(1);
		assertEquals(KeyType.EC, key2.getKeyType());
		assertEquals("2", key2.getKeyID());

		assertEquals(2, matches.size());
	}


	public void testSelectByAlgorithm() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().algorithm(JWSAlgorithm.RS256).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.PS256).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals(KeyType.RSA, key1.getKeyType());
		assertEquals(JWSAlgorithm.RS256, key1.getAlgorithm());
		assertEquals("1", key1.getKeyID());

		assertEquals(1, matches.size());
	}


	public void testSelectByID() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID("1").build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals("1", key1.getKeyID());

		assertEquals(1, matches.size());
	}


	public void testSelectByAnyID() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(null).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals("1", key1.getKeyID());

		RSAKey key2 = (RSAKey)matches.get(1);
		assertEquals("2", key2.getKeyID());

		assertEquals(2, matches.size());
	}


	public void testSelectPrivateOnly() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().privateOnly(true).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
		keyList.add(new OctetSequenceKey.Builder(new Base64URL("k")).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		OctetSequenceKey key1 = (OctetSequenceKey)matches.get(0);
		assertEquals("k", key1.getKeyValue().toString());

		assertEquals(1, matches.size());
	}


	public void testSelectPublicOnly() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().publicOnly(true).build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
		keyList.add(new OctetSequenceKey.Builder(new Base64URL("k")).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals("1", key1.getKeyID());

		assertEquals(1, matches.size());
	}


	public void testMatchComplex() {

		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder()
			.keyType(KeyType.RSA)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.keyID("1")
			.publicOnly(true)
			.build());

		List<JWK> keyList = new ArrayList<>();
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build());
		keyList.add(new RSAKey.Builder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build());

		JWKSet jwkSet = new JWKSet(keyList);

		List<JWK> matches = selector.select(jwkSet);

		RSAKey key1 = (RSAKey)matches.get(0);
		assertEquals("1", key1.getKeyID());

		assertEquals(1, matches.size());
	}
}
