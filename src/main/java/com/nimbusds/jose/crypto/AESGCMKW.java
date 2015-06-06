package com.nimbusds.jose.crypto;


import java.security.Provider;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.util.ByteUtils;
import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.nimbusds.jose.JOSEException;


/**
 * AES GCM methods for Content Encryption Key (CEK) encryption and
 * decryption. Uses the BouncyCastle.org provider. This class is thread-safe.
 *
 * <p>See RFC 7518 (JWA), section 4.7.
 *
 * @author Melisa Halsband
 * @version $version$ (2014-06-18)
 */
@ThreadSafe
class AESGCMKW {


	/**
	 * The standard authentication tag length (128 bits).
	 */
	public static final int AUTH_TAG_BIT_LENGTH = 128;


	/**
	 * Encrypts the specified Content Encryption Key (CEK).
	 *
	 * @param cek	   The Content Encryption Key (CEK) to encrypt. Must
	 *		   not be {@code null}.
	 * @param iv	   The initialisation vector (IV). Must not be
	 *		   {@code null}.
	 * @param kek	   The AES Key Encription Key (KEK). Must not be
	 *		   {@code null}.
	 * @param provider The JCA provider, or {@code null} to use the default
	 *		   one.
	 *
	 * @return The encrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static AuthenticatedCipherText encryptCEK(final SecretKey cek,
							 final byte[] iv,
							 final SecretKey kek,
							 Provider provider)
		throws JOSEException {

		// Initialise AES cipher
		BlockCipher cipher = AES.createCipher(kek, true);

		// Create GCM cipher with AES
		GCMBlockCipher gcm = new GCMBlockCipher(cipher);

		AEADParameters aeadParams = new AEADParameters(new KeyParameter(kek.getEncoded()),
			AUTH_TAG_BIT_LENGTH,
			iv,
			null);
		gcm.init(true, aeadParams);

		// Prepare output buffer
		int outputLength = gcm.getOutputSize(cek.getEncoded().length);
		byte[] output = new byte[outputLength];

		// Produce cipher text
		int outputOffset = gcm.processBytes(cek.getEncoded(), 0, cek.getEncoded().length, output, 0);

		// Produce authentication tag
		try {
			outputOffset += gcm.doFinal(output, outputOffset);

		} catch (InvalidCipherTextException e) {

			throw new JOSEException("Couldn't generate GCM authentication tag for key: " + e.getMessage(), e);
		}

		// Split output into cipher text and authentication tag
		int authTagLength = AUTH_TAG_BIT_LENGTH / 8;

		byte[] cipherText = new byte[outputOffset - authTagLength];
		byte[] authTag = new byte[authTagLength];

		System.arraycopy(output, 0, cipherText, 0, cipherText.length);
		System.arraycopy(output, outputOffset - authTagLength, authTag, 0, authTag.length);

		return new AuthenticatedCipherText(cipherText, authTag);

	}


	/**
	 * Decrypts the specified encrypted Content Encryption Key (CEK).
	 *
	 * @param kek	       The AES Key Encription Key. Must not be
	 *                     {@code null}.
	 * @param iv	       The initialisation vector (IV). Must not be
	 *		       {@code null}.
	 * @param authEncrCEK  The encrypted Content Encryption Key (CEK) to
	 *		       decrypt and authentication tag. Must not be
	 *		       {@code null}.
	 * @param provider     The JCA provider, or {@code null} to use the
	 *		       default one.
	 *
	 * @return The decrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static SecretKey decryptCEK(final SecretKey kek,
					   final byte[] iv,
					   final AuthenticatedCipherText authEncrCEK,
					   final int keyLength,
					   final Provider provider)
		throws JOSEException {

		// Initialise AES cipher
		BlockCipher cipher = AES.createCipher(kek, false);

		// Create GCM cipher with AES
		GCMBlockCipher gcm = new GCMBlockCipher(cipher);

		AEADParameters aeadParams = new AEADParameters(new KeyParameter(kek.getEncoded()),
			AUTH_TAG_BIT_LENGTH,
			iv,
			null);
		gcm.init(false, aeadParams);

		byte[] cipherText = authEncrCEK.getCipherText();
		byte[] authTag = authEncrCEK.getAuthenticationTag();

		// Join encrypted CEK and authentication tag to produce cipher input
		final byte[] input = ByteUtils.concat(cipherText, authTag);
		final int keyBytesLength = gcm.getOutputSize(input.length);
		byte[] keyBytes = new byte[keyBytesLength];

		// Decrypt
		int keyBytesOffset = gcm.processBytes(input, 0, input.length, keyBytes, 0);


		// Validate authentication tag
		try {
			keyBytesOffset += gcm.doFinal(keyBytes, keyBytesOffset);

		} catch (InvalidCipherTextException e) {

			throw new JOSEException("Couldn't validate GCM authentication tag: " + e.getMessage(), e);
		}

		if (8 * keyBytes.length != keyLength) {

			throw new JOSEException("CEK key length mismatch: " +
				keyBytes.length + " != " + keyLength);
		}

		return new SecretKeySpec(keyBytes, "AES");

	}


	/**
	 * Prevents public instantiation.
	 */
	private AESGCMKW() { }
}