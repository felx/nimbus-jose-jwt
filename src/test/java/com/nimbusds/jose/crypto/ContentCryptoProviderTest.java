package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jca.JWEJCAProviderSpec;
import com.nimbusds.jose.util.Base64URL;


/**
 * Tests the content encryption / decryption provider.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
public class ContentCryptoProviderTest extends TestCase {


	public void testCompatibleEncryptionMethods() {

		// 128 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(128).contains(EncryptionMethod.A128GCM));
		assertEquals(1, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(128).size());

		// 192 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(192).contains(EncryptionMethod.A192GCM));
		assertEquals(1, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(192).size());

		// 256 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).contains(EncryptionMethod.A256GCM));
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).contains(EncryptionMethod.A128CBC_HS256_DEPRECATED));
		assertEquals(3, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(256).size());

		// 384 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(384).contains(EncryptionMethod.A192CBC_HS384));
		assertEquals(1, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(384).size());

		// 512 bit cek
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512).contains(EncryptionMethod.A256CBC_HS512));
		assertTrue(ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512).contains(EncryptionMethod.A256CBC_HS512_DEPRECATED));
		assertEquals(2, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(512).size());

		// Total
		assertEquals(5, ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.size());
	}


	public void test_A256CBC_HS512()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		final byte[] clearText = "Hello world!".getBytes(Charset.forName("UTF-8"));
		byte[] cekBytes = new byte[64];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		final Base64URL encryptedKey = null;
		final JWEJCAProviderSpec jcaProvider = new JWEJCAProviderSpec();

		JWECryptoParts jweParts = ContentCryptoProvider.encrypt(
			header,
			clearText,
			cek,
			encryptedKey,
			jcaProvider);

		assertTrue(Arrays.equals(clearText, ContentCryptoProvider.decrypt(
			header,
			encryptedKey,
			jweParts.getInitializationVector(),
			jweParts.getCipherText(),
			jweParts.getAuthenticationTag(),
			cek,
			jcaProvider)));
	}

	public void test_A256CBC_HS512_cekTooShort()
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		final byte[] clearText = "Hello world!".getBytes(Charset.forName("UTF-8"));
		byte[] cekBytes = new byte[32];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		final Base64URL encryptedKey = null;
		final JWEJCAProviderSpec jcaProvider = new JWEJCAProviderSpec();


		try {
			ContentCryptoProvider.encrypt(
				header,
				clearText,
				cek,
				encryptedKey,
				jcaProvider);

		} catch (JOSEException e) {

			assertEquals("Unsupported AES/CBC/PKCS5Padding/HMAC-SHA2 key length, must be 256, 384 or 512 bits", e.getMessage());
		}
	}


	public void test_A256GCM_cekTooShort() // todo
		throws Exception {

		final JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		final byte[] clearText = "Hello world!".getBytes(Charset.forName("UTF-8"));
		byte[] cekBytes = new byte[16];
		new SecureRandom().nextBytes(cekBytes);
		SecretKey cek = new SecretKeySpec(cekBytes, "AES");
		final Base64URL encryptedKey = null;
		final JWEJCAProviderSpec jcaProvider = new JWEJCAProviderSpec();


		try {
			ContentCryptoProvider.encrypt(
				header,
				clearText,
				cek,
				encryptedKey,
				jcaProvider);

		} catch (JOSEException e) {

			assertEquals("Unsupported AES/CBC/PKCS5Padding/HMAC-SHA2 key length, must be 256, 384 or 512 bits", e.getMessage());
		}
	}
}
