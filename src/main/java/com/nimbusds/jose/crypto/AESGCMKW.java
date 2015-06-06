package com.nimbusds.jose.crypto;


import java.security.Provider;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

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

		return AESGCM.encrypt(kek, iv, cek.getEncoded(), new byte[0], provider);
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

		byte[] keyBytes = AESGCM.decrypt(kek, iv, authEncrCEK.getCipherText(), new byte[0], authEncrCEK.getAuthenticationTag(), provider);

		if (8 * keyBytes.length != keyLength) {

			throw new JOSEException("CEK key length mismatch: " +
				keyBytes.length + " != " + keyLength);
		}

		// pad up to key length?
		return new SecretKeySpec(keyBytes, "AES");
	}


	/**
	 * Prevents public instantiation.
	 */
	private AESGCMKW() { }
}