package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.Arrays;

import junit.framework.TestCase;

import com.nimbusds.jose.*;


/**
 * Password-based encryption test.
 */
public class PBES2Test extends TestCase {


	public void testSupportedAlgorithms() {

		JWEEncrypter encrypter = new PasswordBasedEncrypter("secret", 8, 1000);

		assertEquals(3, encrypter.supportedJWEAlgorithms().size());
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(encrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS512_A256KW));

		JWEDecrypter decrypter = new PasswordBasedDecrypter("secret");

		assertEquals(3, decrypter.supportedJWEAlgorithms().size());
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS256_A128KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS384_A192KW));
		assertTrue(decrypter.supportedJWEAlgorithms().contains(JWEAlgorithm.PBES2_HS512_A256KW));
	}


	public void testSupportedEncryptionMethods()
		throws Exception {

		JWEEncrypter encrypter = new PasswordBasedEncrypter("secret", 8, 1000);

		assertEquals(8, encrypter.supportedEncryptionMethods().size());
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192CBC_HS384));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A192GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256GCM));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertTrue(encrypter.supportedEncryptionMethods().contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));

		JWEDecrypter decrypter = new PasswordBasedDecrypter("secret");

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


	public void testConfigConstants() {

		assertEquals(8, PasswordBasedEncrypter.MIN_SALT_LENGTH);
		assertEquals(1000, PasswordBasedEncrypter.MIN_RECOMMENDED_ITERATION_COUNT);
	}


	public void testPasswordByteConstructors() {

		byte[] password = "secret".getBytes(Charset.forName("UTF-8"));

		PasswordBasedEncrypter encrypter = new PasswordBasedEncrypter(password, 8, 1000);

		assertTrue(Arrays.equals(password, encrypter.getPassword()));
		assertEquals("secret", encrypter.getPasswordString());

		assertEquals(8, encrypter.getSaltLength());
		assertEquals(1000, encrypter.getIterationCount());

		PasswordBasedDecrypter decrypter = new PasswordBasedDecrypter(password);

		assertTrue(Arrays.equals(password, decrypter.getPassword()));
		assertEquals("secret", decrypter.getPasswordString());
	}


	public void testPBES2_HS256_A128KW()
		throws Exception {

		final String password = "secret";
		final String plaintext = "Hello world!";

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.PBES2_HS256_A128KW, EncryptionMethod.A128GCM).build(), new Payload(plaintext));

		jweObject.encrypt(new PasswordBasedEncrypter(password, 16, 8192));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new PasswordBasedDecrypter(password));

		assertEquals(plaintext, jweObject.getPayload().toString());
	}


	public void testPBES2_HS384_A192KW()
		throws Exception {

		final String password = "secret";
		final String plaintext = "Hello world!";

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.PBES2_HS384_A192KW, EncryptionMethod.A128CBC_HS256).build(), new Payload(plaintext));

		jweObject.encrypt(new PasswordBasedEncrypter(password, 16, 8192));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new PasswordBasedDecrypter(password));

		assertEquals(plaintext, jweObject.getPayload().toString());
	}


	public void testPBES2_HS512_A256KW()
		throws Exception {

		final String password = "secret";
		final String plaintext = "Hello world!";

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.PBES2_HS512_A256KW, EncryptionMethod.A256CBC_HS512).build(), new Payload(plaintext));

		jweObject.encrypt(new PasswordBasedEncrypter(password, 16, 8192));

		jweObject = JWEObject.parse(jweObject.serialize());

		jweObject.decrypt(new PasswordBasedDecrypter(password));

		assertEquals(plaintext, jweObject.getPayload().toString());
	}
}
