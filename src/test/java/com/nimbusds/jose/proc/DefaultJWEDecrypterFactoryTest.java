package com.nimbusds.jose.proc;


import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.ByteUtils;
import junit.framework.TestCase;


/**
 * Tests the default JWE decrypter factory.
 *
 * @version 2015-06-14
 */
public class DefaultJWEDecrypterFactoryTest extends TestCase {


	private static RSAPrivateKey generateRSAPrivateKey()
		throws Exception {

		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		return (RSAPrivateKey)keyPair.getPrivate();
	}


	public void testCreateRSADecrypter()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM);
		Key key = generateRSAPrivateKey();

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		JWEDecrypter decrypter = factory.createJWEDecrypter(header, key);

		assertTrue(decrypter.supportedJWEAlgorithms().contains(header.getAlgorithm()));
		assertTrue(decrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod()));

		RSADecrypter rsaDecrypter = (RSADecrypter)decrypter;
		assertEquals(key, rsaDecrypter.getPrivateKey());
	}


	public void testCreateRSAOAEPDecrypter()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
		Key key = generateRSAPrivateKey();

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		JWEDecrypter decrypter = factory.createJWEDecrypter(header, key);

		assertTrue(decrypter.supportedJWEAlgorithms().contains(header.getAlgorithm()));
		assertTrue(decrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod()));

		RSADecrypter rsaDecrypter = (RSADecrypter)decrypter;
		assertEquals(key, rsaDecrypter.getPrivateKey());
	}


	private static ECPrivateKey generateECPrivateKey(final ECKey.Curve curve)
		throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		keyGen.initialize(curve.toECParameterSpec());
		return (ECPrivateKey)keyGen.generateKeyPair().getPrivate();
	}


	public void testCreateECDHDecrypter()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256);
		Key key = generateECPrivateKey(ECKey.Curve.P_256);

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		JWEDecrypter decrypter = factory.createJWEDecrypter(header, key);

		assertTrue(decrypter.supportedJWEAlgorithms().contains(header.getAlgorithm()));
		assertTrue(decrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod()));

		ECDHDecrypter ecdhDecrypter = (ECDHDecrypter)decrypter;
		assertEquals(key, ecdhDecrypter.getPrivateKey());
		assertTrue(ecdhDecrypter.supportedEllipticCurves().contains(ECKey.Curve.P_256));
	}


	private static SecretKey generateSharedKey(final int bitLength) {

		byte[] keyBytes = new byte[ByteUtils.byteLength(bitLength)];
		new SecureRandom().nextBytes(keyBytes);
		return new SecretKeySpec(keyBytes, "AES");
	}


	public void testCreateDirectDecrypter()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);
		Key key = generateSharedKey(128);

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		JWEDecrypter decrypter = factory.createJWEDecrypter(header, key);

		assertTrue(decrypter.supportedJWEAlgorithms().contains(header.getAlgorithm()));
		assertTrue(decrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod()));

		DirectDecrypter directDecrypter = (DirectDecrypter)decrypter;
		assertEquals(key, directDecrypter.getKey());
	}


	public void testCreateDirectDecrypterWithIncompatibleKeyLength()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);
		Key key = generateSharedKey(256);

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		try {
			factory.createJWEDecrypter(header, key);
			fail();
		} catch (JOSEException e) {
			assertEquals("Key length (256 bits) is not compatible with A128GCM encryption method", e.getMessage());
		}
	}


	public void testCreateAESDecrypter()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256);
		Key key = generateSharedKey(128);

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		JWEDecrypter decrypter = factory.createJWEDecrypter(header, key);

		assertTrue(decrypter.supportedJWEAlgorithms().contains(header.getAlgorithm()));
		assertTrue(decrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod()));

		AESDecrypter aesDecrypter = (AESDecrypter)decrypter;
		assertEquals(key, aesDecrypter.getKey());
	}


	public void testCreateAESDecrypterWithIncompatibleKeyLength()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256);
		Key key = generateSharedKey(256);

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		try {
			factory.createJWEDecrypter(header, key);
			fail();
		} catch (JOSEException e) {
			assertEquals("Key length (256 bits) is not compatible with A128KW algorithm", e.getMessage());
		}
	}


	public void testCreatePasswordBasedDecrypter()
		throws Exception {

		JWEHeader header = new JWEHeader(JWEAlgorithm.PBES2_HS256_A128KW, EncryptionMethod.A128CBC_HS256);
		Key key = new SecretKeySpec("secret".getBytes(Charset.forName("UTF-8")), "AES");

		JWEDecrypterFactory factory = new DefaultJWEDecrypterFactory();

		JWEDecrypter decrypter = factory.createJWEDecrypter(header, key);

		assertTrue(decrypter.supportedJWEAlgorithms().contains(header.getAlgorithm()));
		assertTrue(decrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod()));

		PasswordBasedDecrypter passwordBasedDecrypter = (PasswordBasedDecrypter)decrypter;
		assertEquals("secret", passwordBasedDecrypter.getPasswordString());
	}
}
