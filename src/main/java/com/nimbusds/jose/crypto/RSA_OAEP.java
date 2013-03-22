package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import com.nimbusds.jose.JOSEException;


/**
 * Static methods for RSAES OAEP Content Master Key (CMK) encryption and
 * decryption. Uses the BouncyCastle.org provider.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
class RSA_OAEP {


	/**
	 * Encrypts the specified Content Master Key (CMK).
	 *
	 * @param publicKey        The public RSA key. Must not be 
	 *                         {@code null}.
	 * @param contentMasterKey The Content Master Key (CMK). Must not be
	 *                         {@code null}.
	 *
	 * @return The encrypted Content Master Key (CMK).
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static byte[] encryptCMK(final RSAPublicKey publicKey,
		                        final SecretKey contentMasterKey)
		throws JOSEException {

		try {
			AsymmetricBlockCipher engine = new RSAEngine();

			// JCA identifier RSA/ECB/OAEPWithSHA-1AndMGF1Padding ?
			OAEPEncoding cipher = new OAEPEncoding(engine);

			BigInteger mod = publicKey.getModulus();
			BigInteger exp = publicKey.getPublicExponent();
			RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
			cipher.init(true, keyParams);

			int inputBlockSize = cipher.getInputBlockSize();
			int outputBlockSize = cipher.getOutputBlockSize();

			byte[] keyBytes = contentMasterKey.getEncoded();

			return cipher.processBlock(keyBytes, 0, keyBytes.length);

		} catch (Exception e) {

			// org.bouncycastle.crypto.InvalidCipherTextException
			throw new JOSEException(e.getMessage(), e);
		}
	}

	
	/**
	 * Decrypts the Content Master Key (CMK).
	 *
	 * @param privateKey   The private RSA key. Must not be {@code null}.
	 * @param encryptedCMK The encrypted Content Master Key (CMK). Must not
	 *                     be {@code null}.
	 *
	 * @return The decrypted Content Master Key (CMK).
	 *
	 * @throws JOSEException If derivation failed.
	 */
	public static SecretKeySpec decryptCMK(final RSAPrivateKey privateKey, 
		                               final byte[] encryptedCMK)
		throws JOSEException {

		try {
			RSAEngine engine = new RSAEngine();
			OAEPEncoding cipher = new OAEPEncoding(engine);
			
			BigInteger mod = privateKey.getModulus();
			BigInteger exp = privateKey.getPrivateExponent();

			RSAKeyParameters keyParams = new RSAKeyParameters(true, mod, exp);
			cipher.init(false, keyParams);
			byte[] secretKeyBytes = cipher.processBlock(encryptedCMK, 0, encryptedCMK.length);
			return new SecretKeySpec(secretKeyBytes, "AES");

		} catch (Exception e) {

			// org.bouncycastle.crypto.InvalidCipherTextException
			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private RSA_OAEP() { }
}