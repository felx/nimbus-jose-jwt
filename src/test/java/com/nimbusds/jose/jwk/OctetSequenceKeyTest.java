package com.nimbusds.jose.jwk;


import java.net.URI;
import java.security.SecureRandom;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the Octet Sequence JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-23
 */
public class OctetSequenceKeyTest extends TestCase {


	public void testConstructorAndSerialization()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

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
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<>();
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

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

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
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new LinkedList<>();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

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


	public void testBuilderWithByteArray()
		throws Exception {

		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);

		OctetSequenceKey oct = new OctetSequenceKey.Builder(key).build();

		assertEquals(Base64URL.encode(key), oct.getKeyValue());
	}


	public void testBuilderWithSecretKey()
		throws Exception {

		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);

		OctetSequenceKey oct = new OctetSequenceKey.Builder(new SecretKeySpec(key, "MAC")).keyUse(KeyUse.SIGNATURE).build();

		SecretKey secretKey = oct.toSecretKey();
		assertTrue(Arrays.equals(key, secretKey.getEncoded()));
		assertEquals("NONE", secretKey.getAlgorithm());
	}


	public void testCookbookHMACKeyExample()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7c520#section-3.5
		
		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
			"\"use\":\"sig\","+
			"\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);

		assertEquals(KeyType.OCT, jwk.getKeyType());
		assertEquals("018c0ae5-4d9b-471b-bfd6-eef314bc7037", jwk.getKeyID());
		assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());

		assertEquals("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", jwk.getKeyValue().toString());
	}


	public void testCookbookAESKeyExample()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-5.3.1

		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"77c7e2b8-6e13-45cf-8672-617b5b45243a\","+
			"\"use\":\"enc\","+
			"\"alg\":\"A128GCM\","+
			"\"k\":\"XctOhJAkA-pD9Lh7ZgW_2A\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);

		assertEquals(KeyType.OCT, jwk.getKeyType());
		assertEquals("77c7e2b8-6e13-45cf-8672-617b5b45243a", jwk.getKeyID());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(EncryptionMethod.A128GCM, jwk.getAlgorithm());

		assertEquals("XctOhJAkA-pD9Lh7ZgW_2A", jwk.getKeyValue().toString());
	}


	public void testToSecretKey() {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

		assertTrue(Arrays.equals(k.decode(), jwk.toSecretKey().getEncoded()));
		assertEquals("NONE", jwk.toSecretKey().getAlgorithm());
	}


	public void testToSecretKeyWithAlg() {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

		assertTrue(Arrays.equals(k.decode(), jwk.toSecretKey("AES").getEncoded()));
		assertEquals("AES", jwk.toSecretKey("AES").getAlgorithm());
	}
}