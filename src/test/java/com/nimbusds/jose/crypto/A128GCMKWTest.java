package com.nimbusds.jose.crypto;


import java.util.Arrays;
import java.util.HashSet;

import junit.framework.TestCase;
import org.junit.Assert;

import com.nimbusds.jose.*;


/**
 * Tests A128GCMKW JWE encryption and decryption. 
 *
 * @author Melisa Halsband 
 * @version $version$ (2014-08-19)
 */
public class A128GCMKWTest extends TestCase {


	// 128-bit shared symmetric key
	private final static byte[] key128 = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226 };


	public void testKeyLength() {

		assertEquals(128, key128.length * 8);
	}


	public void testSupportedAlgorithms()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key128);

		assertEquals(6, encrypter.supportedJWEAlgorithms().size());
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A192KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128GCMKW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A192GCMKW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256GCMKW));

		JWEDecrypter decrypter = new AESDecrypter(key128);

		assertEquals(6, decrypter.supportedJWEAlgorithms().size());
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A192KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A128GCMKW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A192GCMKW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.A256GCMKW));
	}


	public void testSupportedEncryptionMethods()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key128);

		assertEquals(8, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		JWEDecrypter decrypter = new AESDecrypter(key128);

		assertEquals(8, decrypter.supportedEncryptionMethods().size());
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(decrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
	}


	public void testGetAcceptedAlgorithms()
		throws Exception {

		JWEDecrypter decrypter = new AESDecrypter(key128);

		assertEquals(2, decrypter.getAcceptedAlgorithms().size());
		assertTrue(decrypter.getAcceptedAlgorithms().contains(JWEAlgorithm.A128KW));
		assertTrue(decrypter.getAcceptedAlgorithms().contains(JWEAlgorithm.A128GCMKW));
	}


	public void testGetAcceptedEncryptionMethods()
		throws Exception {

		JWEDecrypter decrypter = new AESDecrypter(key128);

		assertEquals(8, decrypter.getAcceptedEncryptionMethods().size());
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
	}


	public void testSetAcceptedAlgorithms()
		throws Exception {

		JWEDecrypter decrypter = new AESDecrypter(key128);

		try {
			decrypter.setAcceptedAlgorithms(null);
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		try {
			decrypter.setAcceptedAlgorithms(new HashSet<>(Arrays.asList(JWEAlgorithm.RSA1_5)));
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		decrypter.setAcceptedAlgorithms(new HashSet<>(Arrays.asList(JWEAlgorithm.A128GCMKW)));
		assertTrue(decrypter.getAcceptedAlgorithms().contains(JWEAlgorithm.A128GCMKW));
		assertEquals(1, decrypter.getAcceptedAlgorithms().size());
	}


	public void testSetAcceptedEncryptionMethods()
		throws Exception {

		JWEDecrypter decrypter = new AESDecrypter(key128);

		try {
			decrypter.setAcceptedEncryptionMethods(null);
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		try {
			decrypter.setAcceptedEncryptionMethods(new HashSet<>(Arrays.asList(new EncryptionMethod("unsupported"))));
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		decrypter.setAcceptedEncryptionMethods(new HashSet<>(Arrays.asList(EncryptionMethod.A128GCM)));
		assertTrue(decrypter.getAcceptedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertEquals(1, decrypter.getAcceptedEncryptionMethods().size());
	}


	public void testWithA128CBC_HS256()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		Assert.assertArrayEquals(key128, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}

	public void testWithA192CBC_HS384()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A192CBC_HS384);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		Assert.assertArrayEquals(key128, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		Assert.assertArrayEquals(key128, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA128GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		Assert.assertArrayEquals(key128, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A192GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		Assert.assertArrayEquals(key128, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256GCM);
		Payload payload = new Payload("I think therefore I am.");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		Assert.assertArrayEquals(key128, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		Assert.assertArrayEquals(key128, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("I think therefore I am.", payload.toString());
	}

	public void testWithCompression()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new AESDecrypter(key128);
		decrypter.getIgnoredCriticalHeaderParameters().add("exp");

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new AESDecrypter(key128);

		try {
			jweObject.decrypt(decrypter);
			fail();
		} catch (JOSEException e) {
			// ok
			assertEquals("Unsupported critical header parameter", e.getMessage());
		}
	}


	public void testWithDeprecatedA128CBC_HS256()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A128CBC_HS256_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithDeprecatedA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key128);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key128);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}
}
