package com.nimbusds.jose.jwk;


import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the Octet Sequence JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-30)
 */
public class OctetSequenceKeyTest extends TestCase {


	public void testConstructorAndSerialization()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		OctetSequenceKey key = new OctetSequenceKey(k, Use.SIGNATURE, JWSAlgorithm.HS256, "1", x5u, x5t, x5c);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(Use.SIGNATURE, key.getKeyUse());
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
		assertEquals(Use.SIGNATURE, key.getKeyUse());
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


	public void testBuilder()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URL x5u = new URL("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<Base64>();
		x5c.add(new Base64("def"));

		OctetSequenceKey key = new OctetSequenceKey.Builder(k).
		                       setKeyUse(Use.SIGNATURE).
		                       setAlgorithm(JWSAlgorithm.HS256).
		                       setKeyID("1").
		                       setX509CertURL(x5u).
		                       setX509CertThumbprint(x5t).
		                       setX509CertChain(x5c).
		                       build();

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(Use.SIGNATURE, key.getKeyUse());
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
		assertEquals(Use.SIGNATURE, key.getKeyUse());
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