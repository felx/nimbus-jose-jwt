package com.nimbusds.jose.crypto;


import java.util.Arrays;
import java.util.HashSet;

import junit.framework.TestCase;
import org.junit.Assert;

import com.nimbusds.jose.*;


/**
 * Tests A192GCMKW JWE encryption and decryption. 
 *
 * @author Melisa Halsband 
 * @version $version$ (2014-08-19)
 */
public class A192GCMKWTest extends TestCase {


	// 192-bit shared symmetric key
	private final static byte[] key192 = {
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121,
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226,
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61 };


	public void testKeyLength() {

		assertEquals(192, key192.length * 8);
	}


	public void testSupportedAlgorithms()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key192);

		assertEquals(6, encrypter.supportedAlgorithms().size());
		assertTrue(encrypter.supportedAlgorithms().contains(JWEAlgorithm.A128KW));
		assertTrue(encrypter.supportedAlgorithms().contains(JWEAlgorithm.A192KW));
		assertTrue(encrypter.supportedAlgorithms().contains(JWEAlgorithm.A256KW));
		assertTrue(encrypter.supportedAlgorithms().contains(JWEAlgorithm.A128GCMKW));
		assertTrue(encrypter.supportedAlgorithms().contains(JWEAlgorithm.A192GCMKW));
		assertTrue(encrypter.supportedAlgorithms().contains(JWEAlgorithm.A256GCMKW));

		JWEDecrypter decrypter = new AESDecrypter(key192);

		assertEquals(6, decrypter.supportedAlgorithms().size());
		assertTrue(decrypter.supportedAlgorithms().contains(JWEAlgorithm.A128KW));
		assertTrue(decrypter.supportedAlgorithms().contains(JWEAlgorithm.A192KW));
		assertTrue(decrypter.supportedAlgorithms().contains(JWEAlgorithm.A256KW));
		assertTrue(decrypter.supportedAlgorithms().contains(JWEAlgorithm.A128GCMKW));
		assertTrue(decrypter.supportedAlgorithms().contains(JWEAlgorithm.A192GCMKW));
		assertTrue(decrypter.supportedAlgorithms().contains(JWEAlgorithm.A256GCMKW));
	}


	public void testSupportedEncryptionMethods()
		throws Exception {

		JWEEncrypter encrypter = new AESEncrypter(key192);

		assertEquals(8, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		JWEDecrypter decrypter = new AESDecrypter(key192);

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

		JWEDecrypter decrypter = new AESDecrypter(key192);

		assertEquals(2, decrypter.getAcceptedAlgorithms().size());
		assertTrue(decrypter.getAcceptedAlgorithms().contains(JWEAlgorithm.A192KW));
		assertTrue(decrypter.getAcceptedAlgorithms().contains(JWEAlgorithm.A192GCMKW));
	}


	public void testGetAcceptedEncryptionMethods()
		throws Exception {

		JWEDecrypter decrypter = new AESDecrypter(key192);

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

		JWEDecrypter decrypter = new AESDecrypter(key192);

		try {
			decrypter.setAcceptedAlgorithms(null);
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		try {
			decrypter.setAcceptedAlgorithms(new HashSet<>(Arrays.asList(JWEAlgorithm.A128KW)));
			fail();
		} catch (IllegalArgumentException e) {
			// ok
		}

		decrypter.setAcceptedAlgorithms(new HashSet<>(Arrays.asList(JWEAlgorithm.A192GCMKW)));
		assertTrue(decrypter.getAcceptedAlgorithms().contains(JWEAlgorithm.A192GCMKW));
		assertEquals(1, decrypter.getAcceptedAlgorithms().size());
	}


	public void testSetAcceptedEncryptionMethods()
		throws Exception {

		JWEDecrypter decrypter = new AESDecrypter(key192);

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

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		Assert.assertArrayEquals(key192, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		Assert.assertArrayEquals(key192, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}

	public void testWithA192CBC_HS384()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A192CBC_HS384);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		Assert.assertArrayEquals(key192, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		Assert.assertArrayEquals(key192, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A256CBC_HS512);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		Assert.assertArrayEquals(key192, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		Assert.assertArrayEquals(key192, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA128GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A128GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		Assert.assertArrayEquals(key192, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		Assert.assertArrayEquals(key192, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA192GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A192GCM);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		Assert.assertArrayEquals(key192, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		Assert.assertArrayEquals(key192, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithA256GCM()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A256GCM);
		Payload payload = new Payload("I think therefore I am.");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		Assert.assertArrayEquals(key192, ((AESEncrypter)encrypter).getKey().getEncoded());

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		Assert.assertArrayEquals(key192, ((AESDecrypter)decrypter).getKey().getEncoded());

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("I think therefore I am.", payload.toString());
	}

	public void testWithCompression()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A192GCMKW, EncryptionMethod.A128CBC_HS256).
			compressionAlgorithm(CompressionAlgorithm.DEF).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A192GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new AESEncrypter(key192);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new AESDecrypter(key192);
		decrypter.getIgnoredCriticalHeaderParameters().add("exp");

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testCritHeaderParamReject()
		throws Exception {

		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A192GCMKW, EncryptionMethod.A128CBC_HS256).
			customParam("exp", "2014-04-24").
			criticalParams(new HashSet<>(Arrays.asList("exp"))).
			build();

		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		JWEEncrypter encrypter = new AESEncrypter(key192);

		jweObject.encrypt(encrypter);

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		JWEDecrypter decrypter = new AESDecrypter(key192);

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

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A128CBC_HS256_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}


	public void testWithDeprecatedA256CBC_HS512()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A256CBC_HS512_DEPRECATED);
		Payload payload = new Payload("Hello world!");

		JWEObject jweObject = new JWEObject(header, payload);

		assertEquals("State check", JWEObject.State.UNENCRYPTED, jweObject.getState());

		JWEEncrypter encrypter = new AESEncrypter(key192);

		jweObject.encrypt(encrypter);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		String jweString = jweObject.serialize();

		jweObject = JWEObject.parse(jweString);

		assertEquals("State check", JWEObject.State.ENCRYPTED, jweObject.getState());

		JWEDecrypter decrypter = new AESDecrypter(key192);

		jweObject.decrypt(decrypter);

		assertEquals("State check", JWEObject.State.DECRYPTED, jweObject.getState());

		payload = jweObject.getPayload();

		assertEquals("Hello world!", payload.toString());
	}
}
