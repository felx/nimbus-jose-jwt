package com.nimbusds.jose.jwk;


import java.net.URL;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the Octet Sequence JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-20)
 */
public class OctetSequenceKeyTest extends TestCase {


	public void testConstructorAndSerialization()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = new LinkedHashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		OctetSequenceKey key = new OctetSequenceKey(k, null, ops, JWSAlgorithm.HS256, "1", x5u, x5t, x5c);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());

		String jwkString = key.toJSONObject().toString();

		key = OctetSequenceKey.parse(jwkString);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			assertEquals(keyBytes[i], key.toByteArray()[i]);

		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testAltConstructorAndSerialization()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		OctetSequenceKey key = new OctetSequenceKey(k, KeyUse.SIGNATURE, null, JWSAlgorithm.HS256, "1", x5u, x5t, x5c);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());

		String jwkString = key.toJSONObject().toString();

		key = OctetSequenceKey.parse(jwkString);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			assertEquals(keyBytes[i], key.toByteArray()[i]);

		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testRejectUseAndOpsTogether() {

		Set<KeyOperation> ops = new LinkedHashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		try {
			new OctetSequenceKey(new Base64URL("GawgguFyGrWKav7AX4VKUg"), KeyUse.SIGNATURE, ops, null, null, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}
	}


	public void testBuilder()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = new LinkedHashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		OctetSequenceKey key = new OctetSequenceKey.Builder(k).
			keyOperations(ops).
			algorithm(JWSAlgorithm.HS256).
			keyID("1").
			x509CertURL(x5u).
			x509CertThumbprint(x5t).
			x509CertChain(x5c).
			build();

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());


		String jwkString = key.toJSONObject().toString();

		key = OctetSequenceKey.parse(jwkString);


		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}
}