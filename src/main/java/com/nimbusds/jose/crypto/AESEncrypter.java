package com.nimbusds.jose.crypto;

import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;


/**
 * AES encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A128GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A192GCMKW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#A256GCMKW}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author Melisa Halsband 
 * @version $version$ (2014-08-20)
 */
@ThreadSafe
public class AESEncrypter extends AESCryptoProvider implements JWEEncrypter {


	/**
	 * Constants used for clarity.
	 */
	private static enum AlgFamily {

		AESKW, AESGCMKW
	}


	/**
	 * The key encrypting key.
	 */
	private final SecretKey kek;


	/**
	 * Creates a new AES encrypter.
	 *
	 * @param kek The Key Encrypting Key. Must be 128 bits (16 bytes), 192
	 *            bits (24 bytes) or 256 bits (32 bytes). Must not be
	 *            {@code null}.
	 */
	public AESEncrypter(final SecretKey kek) {

		if (kek == null) {
			throw new IllegalArgumentException("The Key Encrypting Key must not be null");
		}

		this.kek = kek;
	}

	/**
	 * Creates a new AES encrypter.
	 *
	 * @param keyBytes The Key Encrypting Key, as a byte array. Must be 128
	 *                 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32
	 *                 bytes). Must not be {@code null}.
	 */
	public AESEncrypter(final byte[] keyBytes) {

		this(new SecretKeySpec(keyBytes, "AES"));
	}


	/**
	 * Gets the Key Encrypting Key.
	 *
	 * @return The Key Encrypting Key.
	 */
	public SecretKey getKey() {

		return kek;
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] bytes)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final EncryptionMethod enc = header.getEncryptionMethod();

		// Generate and encrypt the CEK according to the enc method
		final SecureRandom randomGen = getSecureRandom();
		final SecretKey cek = AES.generateKey(enc.cekBitLength(), randomGen);
		byte[] keyIV;

		final AuthenticatedCipherText authCiphCEK;

		AlgFamily algFamily;

		Base64URL encryptedKey; // The second JWE part

		if (alg.equals(JWEAlgorithm.A128KW)) {

			if(kek.getEncoded().length != 16){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 128 bits for A128KW encryption");
			}
			algFamily = AlgFamily.AESKW;

		} else if (alg.equals(JWEAlgorithm.A192KW)) {

			if(kek.getEncoded().length != 24){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 192 bits for A192KW encryption");
			}
			algFamily = AlgFamily.AESKW;

		} else if (alg.equals(JWEAlgorithm.A256KW)) {

			if (kek.getEncoded().length != 32) {
				throw new JOSEException("The Key Encryption Key (KEK) length must be 256 bits for A256KW encryption");
			}
			algFamily = AlgFamily.AESKW;

		} else if (alg.equals(JWEAlgorithm.A128GCMKW)) {

			if(kek.getEncoded().length != 16){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 128 bits for A128GCMKW encryption");
			}
			algFamily = AlgFamily.AESGCMKW;

		} else if (alg.equals(JWEAlgorithm.A192GCMKW)) {

			if(kek.getEncoded().length != 24){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 192 bits for A192GCMKW encryption");
			}
			algFamily = AlgFamily.AESGCMKW;

		} else if (alg.equals(JWEAlgorithm.A256GCMKW)) {

			if(kek.getEncoded().length != 32){
				throw new JOSEException("The Key Encryption Key (KEK) length must be 256 bits for A256GCMKW encryption");
			}
			algFamily = AlgFamily.AESGCMKW;

		} else {

			throw new JOSEException("Unsupported JWE algorithm, must be A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW orA256GCMKW");
		}

		// We need to work on the header
		JWEHeader modifiableHeader;

		if(AlgFamily.AESKW.name().equals(algFamily)) {
			encryptedKey = Base64URL.encode(AESKW.encryptCEK(cek, kek));
			modifiableHeader = header; // simply copy ref
		} else if(AlgFamily.AESGCMKW.name().equals(algFamily)) {
			keyIV = AESGCM.generateIV(randomGen);
			authCiphCEK = AESGCMKW.encryptCEK(cek, keyIV, kek, keyEncryptionProvider);
			encryptedKey = Base64URL.encode(authCiphCEK.getCipherText());

			// Add iv and tag to the header
			modifiableHeader = new JWEHeader.Builder(header).
				iv(Base64URL.encode(keyIV)).
				authTag(Base64URL.encode(authCiphCEK.getAuthenticationTag())).
				build();
		} else {
			// This should never happen
			throw new JOSEException("Unsupported JWE algorithm, must be A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW orA256GCMKW");
		}

		// Apply compression if instructed
		byte[] plainText = DeflateHelper.applyCompression(modifiableHeader, bytes);

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(modifiableHeader.toBase64URL().toString());

		// Encrypt the plain text according to the JWE enc
		byte[] iv;
		AuthenticatedCipherText authCipherText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) ||
		    enc.equals(EncryptionMethod.A192CBC_HS384) ||
		    enc.equals(EncryptionMethod.A256CBC_HS512)	 ) {

			iv = AESCBC.generateIV(randomGen);

			authCipherText = AESCBC.encryptAuthenticated(
				cek, iv, plainText, aad,
				contentEncryptionProvider, macProvider);

		} else if (enc.equals(EncryptionMethod.A128GCM) ||
			   enc.equals(EncryptionMethod.A192GCM) ||
			   enc.equals(EncryptionMethod.A256GCM)    ) {

			iv = AESGCM.generateIV(randomGen);

			authCipherText = AESGCM.encrypt(
				cek, iv, plainText, aad,
				contentEncryptionProvider);

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			   enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)    ) {

			iv = AESCBC.generateIV(randomGen);

			authCipherText = AESCBC.encryptWithConcatKDF(
				modifiableHeader, cek, encryptedKey, iv, plainText,
				contentEncryptionProvider, macProvider);

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
		}

		return new JWECryptoParts(
			modifiableHeader,
			encryptedKey,
			Base64URL.encode(iv),
			Base64URL.encode(authCipherText.getCipherText()),
			Base64URL.encode(authCipherText.getAuthenticationTag()));
	}
}
