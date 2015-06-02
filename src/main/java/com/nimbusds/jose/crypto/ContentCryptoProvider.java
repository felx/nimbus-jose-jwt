package com.nimbusds.jose.crypto;


import java.util.*;
import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;


/**
 * JWE content encryption / decryption provider.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
class ContentCryptoProvider {


	/**
	 * The supported encryption methods.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


	/**
	 * The encryption methods compatible with each key size in bits.
	 */
	public static final Map<Integer,Set<EncryptionMethod>> COMPATIBLE_ENCRYPTION_METHODS;


	static {
		Set<EncryptionMethod> methods = new LinkedHashSet<>();
		methods.add(EncryptionMethod.A128CBC_HS256);
		methods.add(EncryptionMethod.A192CBC_HS384);
		methods.add(EncryptionMethod.A256CBC_HS512);
		methods.add(EncryptionMethod.A128GCM);
		methods.add(EncryptionMethod.A192GCM);
		methods.add(EncryptionMethod.A256GCM);
		methods.add(EncryptionMethod.A128CBC_HS256_DEPRECATED);
		methods.add(EncryptionMethod.A256CBC_HS512_DEPRECATED);
		SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(methods);

		Map<Integer,Set<EncryptionMethod>> encsMap = new HashMap<>();
		Set<EncryptionMethod> bit128Encs = new HashSet<>();
		Set<EncryptionMethod> bit192Encs = new HashSet<>();
		Set<EncryptionMethod> bit256Encs = new HashSet<>();
		Set<EncryptionMethod> bit384Encs = new HashSet<>();
		Set<EncryptionMethod> bit512Encs = new HashSet<>();
		bit128Encs.add(EncryptionMethod.A128GCM);
		bit192Encs.add(EncryptionMethod.A192GCM);
		bit256Encs.add(EncryptionMethod.A256GCM);
		bit256Encs.add(EncryptionMethod.A128CBC_HS256);
		bit256Encs.add(EncryptionMethod.A128CBC_HS256_DEPRECATED);
		bit384Encs.add(EncryptionMethod.A192CBC_HS384);
		bit512Encs.add(EncryptionMethod.A256CBC_HS512);
		bit512Encs.add(EncryptionMethod.A256CBC_HS512_DEPRECATED);
		encsMap.put(128,Collections.unmodifiableSet(bit128Encs));
		encsMap.put(192,Collections.unmodifiableSet(bit192Encs));
		encsMap.put(256,Collections.unmodifiableSet(bit256Encs));
		encsMap.put(384,Collections.unmodifiableSet(bit384Encs));
		encsMap.put(512, Collections.unmodifiableSet(bit512Encs));
		COMPATIBLE_ENCRYPTION_METHODS = Collections.unmodifiableMap(encsMap);
	}


	/**
	 * Encrypts the specified clear text (content).
	 *
	 * @param header       The final JWE header. Must not be {@code null}.
	 * @param clearText    The clear text to encrypt and optionally
	 *                     compress. Must not be {@code null}.
	 * @param cek          The Content Encryption Key (CEK). Must not be
	 *                     {@code null}.
	 * @param encryptedKey The encrypted CEK, {@code null} if not required.
	 * @param jcaProvider  The JWE JCA provider specification. Must not be
	 *                     {@code null}.
	 *
	 * @return The JWE crypto parts.
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static JWECryptoParts encrypt(final JWEHeader header,
					     final byte[] clearText,
					     final SecretKey cek,
					     final Base64URL encryptedKey,
					     final JWEJCAContext jcaProvider)
		throws JOSEException {

		// Apply compression if instructed
		byte[] plainText = DeflateHelper.applyCompression(header, clearText);

		// Compose the AAD
		byte[] aad = AAD.compute(header);

		// Encrypt the plain text according to the JWE enc
		byte[] iv;
		AuthenticatedCipherText authCipherText;

		if (    header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256) ||
			header.getEncryptionMethod().equals(EncryptionMethod.A192CBC_HS384) ||
			header.getEncryptionMethod().equals(EncryptionMethod.A256CBC_HS512)    ) {

			iv = AESCBC.generateIV(jcaProvider.getSecureRandom());

			authCipherText = AESCBC.encryptAuthenticated(
				cek, iv, plainText, aad,
				jcaProvider.getContentEncryptionProvider(),
				jcaProvider.getMACProvider());

		} else if (header.getEncryptionMethod().equals(EncryptionMethod.A128GCM) ||
			   header.getEncryptionMethod().equals(EncryptionMethod.A192GCM) ||
			   header.getEncryptionMethod().equals(EncryptionMethod.A256GCM)    ) {

			iv = AESGCM.generateIV(jcaProvider.getSecureRandom());

			authCipherText = AESGCM.encrypt(
				cek, iv, plainText, aad,
				jcaProvider.getContentEncryptionProvider());

		} else if (header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			   header.getEncryptionMethod().equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)    ) {

			iv = AESCBC.generateIV(jcaProvider.getSecureRandom());

			authCipherText = AESCBC.encryptWithConcatKDF(
				header, cek, encryptedKey, iv, plainText,
				jcaProvider.getContentEncryptionProvider(),
				jcaProvider.getMACProvider());

		} else {

			throw new JOSEException(AlgorithmSupportMessage.unsupportedEncryptionMethod(
				header.getEncryptionMethod(),
				SUPPORTED_ENCRYPTION_METHODS));
		}

		return new JWECryptoParts(
			header,
			encryptedKey,
			Base64URL.encode(iv),
			Base64URL.encode(authCipherText.getCipherText()),
			Base64URL.encode(authCipherText.getAuthenticationTag()));
	}


	/**
	 * Decrypts the specified cipher text.
	 *
	 * @param header       The JWE header. Must not be {@code null}.
	 * @param encryptedKey The encrypted key, {@code null} if not
	 *                     specified.
	 * @param iv           The initialisation vector (IV). Must not be
	 *                     {@code null}.
	 * @param cipherText   The cipher text. Must not be {@code null}.
	 * @param authTag      The authentication tag. Must not be
	 *                     {@code null}.
	 * @param cek          The Content Encryption Key (CEK). Must not be
	 *                     {@code null}.
	 * @param jcaProvider  The JWE JCA provider specification. Must not be
	 *                     {@code null}.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static byte[] decrypt(final JWEHeader header,
				     final Base64URL encryptedKey,
				     final Base64URL iv,
				     final Base64URL cipherText,
				     final Base64URL authTag,
				     final SecretKey cek,
				     final JWEJCAContext jcaProvider)
		throws JOSEException {

		// Compose the AAD
		byte[] aad = AAD.compute(header);

		// Decrypt the cipher text according to the JWE enc

		byte[] plainText;

		if (header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256) ||
			header.getEncryptionMethod().equals(EncryptionMethod.A192CBC_HS384) ||
			header.getEncryptionMethod().equals(EncryptionMethod.A256CBC_HS512)) {

			plainText = AESCBC.decryptAuthenticated(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				jcaProvider.getContentEncryptionProvider(),
				jcaProvider.getMACProvider());

		} else if (header.getEncryptionMethod().equals(EncryptionMethod.A128GCM) ||
			header.getEncryptionMethod().equals(EncryptionMethod.A192GCM) ||
			header.getEncryptionMethod().equals(EncryptionMethod.A256GCM)) {

			plainText = AESGCM.decrypt(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				jcaProvider.getContentEncryptionProvider());

		} else if (header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			header.getEncryptionMethod().equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)) {

			plainText = AESCBC.decryptWithConcatKDF(
				header,
				cek,
				encryptedKey,
				iv,
				cipherText,
				authTag,
				jcaProvider.getContentEncryptionProvider(),
				jcaProvider.getMACProvider());

		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedEncryptionMethod(
				header.getEncryptionMethod(),
				SUPPORTED_ENCRYPTION_METHODS));
		}


		// Apply decompression if requested
		return DeflateHelper.applyDecompression(header, plainText);
	}
}
