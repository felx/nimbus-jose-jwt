package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;


/**
 * Elliptic Curve Diffie-Hellman key agreement.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-13)
 */
class ECDH {


	/**
	 * Derives a shared secret (also called 'Z') from the specified ECDH
	 * key agreement.
	 *
	 * @param publicKey  The public EC key, i.e. the consumer's public EC
	 *                   key on encryption, or the ephemeral public EC key
	 *                   on decryption. Must not be {@code null}.
	 * @param privateKey The private EC Key, i.e. the ephemeral private EC
	 *                   key on encryption, or the consumer's private EC
	 *                   key on decryption. Must not be {@code null}.
	 * @param provider   The specific JCA provider for the ECDH key
	 *                   agreement, {@code null} to use the default one.
	 *
	 * @return The derived shared secret ('Z'), with algorithm "AES".
	 *
	 * @throws JOSEException If derivation of the shared secret failed.
	 */
	public static SecretKey deriveSharedSecret(final ECPublicKey publicKey,
						   final ECPrivateKey privateKey,
						   final Provider provider)
		throws JOSEException {

		// Get an ECDH key agreement instance from the JCA provider
		KeyAgreement keyAgreement;

		try {
			if (provider != null) {
				keyAgreement = KeyAgreement.getInstance("ECDH", provider);
			} else {
				keyAgreement = KeyAgreement.getInstance("ECDH");
			}

		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException("Couldn't get an ECDH key agreement instance: " + e.getMessage(), e);
		}

		try {
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);

		} catch (InvalidKeyException e) {
			throw new JOSEException("Invalid key for ECDH key agreement: " + e.getMessage(), e);
		}

		return new SecretKeySpec(keyAgreement.generateSecret(), "AES");
	}
}
