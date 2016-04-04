package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;


/**
 * Tests AES/GCM using BouncyCastle API for Java 6.
 */
public class LegacyAESGCMTest extends TestCase {


	public void testEncryptDecrypt()
		throws Exception {

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();

		byte[] iv = AESGCM.generateIV(new SecureRandom());
		byte[] plainText = "Hello world!".getBytes(Charset.forName("UTF-8"));
		byte[] authData = "abc".getBytes(Charset.forName("UTF-8"));

		AuthenticatedCipherText cipherText = LegacyAESGCM.encrypt(secretKey, iv, plainText, authData);

		byte[] decryptedPlainText = LegacyAESGCM.decrypt(secretKey, iv, cipherText.getCipherText(), authData, cipherText.getAuthenticationTag());

		assertEquals("Hello world!", new String(decryptedPlainText, Charset.forName("UTF-8")));
	}
}

