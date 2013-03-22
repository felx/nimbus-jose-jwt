package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

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
	 * @return The encrypted content master key.
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
	 * Prevents public instantiation.
	 */
	private RSA_OAEP() { }
}