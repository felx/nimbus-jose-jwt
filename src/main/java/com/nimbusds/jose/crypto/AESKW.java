package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESWrapEngine;

import com.nimbusds.jose.JOSEException;


/**
 * AES Key Wrapping methods for Content Encryption Key (CEK) encryption and
 * decryption. Uses the BouncyCastle.org provider. This class is thread-safe.
 *
 * <p>See RFC 7518 (JWA), section 4.4.
 *
 * @author Melisa Halsband
 * @version $version$ (2015-05-14)
 */
@ThreadSafe
class AESKW {


	/**
	 * Encrypts the specified Content Encryption Key (CEK).
	 *
	 * @param cek The Content Encryption Key (CEK) to encrypt. Must not be
	 *            {@code null}.
	 * @param kek The AES Key Encryption Key (KEK). Must not be
	 *            {@code null}.
	 *
	 * @return The encrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static byte[] encryptCEK(final SecretKey cek, final SecretKey kek, final Provider provider)
		throws JOSEException {

		try {
			Cipher cipher;

			if (provider != null) {
				cipher = Cipher.getInstance("AESWrap", provider);
			} else {
				cipher = Cipher.getInstance("AESWrap");
			}

			cipher.init(Cipher.WRAP_MODE, kek);

			return cipher.wrap(cek);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException e) {

			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Decrypts the specified encrypted Content Encryption Key (CEK).
	 *
	 * @param kek          The AES Key Encryption Key. Must not be
	 *                     {@code null}.
	 * @param encryptedCEK The encrypted Content Encryption Key (CEK) to
	 *                     decrypt and authentication tag. Must not be
	 *                     {@code null}.
	 *
	 * @return The decrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static SecretKey decryptCEK(final SecretKey kek,
					   final byte[] encryptedCEK)
		throws JOSEException {

		// Create and initialise AES unwrapper
		Wrapper decrypter = new AESWrapEngine();
		decrypter.init(false, new KeyParameter(kek.getEncoded()));

		// decrypt
		byte[] cekBytes;

		try {
			cekBytes = decrypter.unwrap(encryptedCEK, 0, encryptedCEK.length);

		} catch (Exception e) {
			// java.lang.IllegalStateException
			// org.bouncycastle.crypto.InvalidCipherTextException
			throw new JOSEException("Couldn't decrypt Content Encryption Key (CEK): " + e.getMessage(), e);
		}

		return new SecretKeySpec(cekBytes, "AES");
	}


	/**
	 * Prevents public instantiation.
	 */
	private AESKW() {
	}
}