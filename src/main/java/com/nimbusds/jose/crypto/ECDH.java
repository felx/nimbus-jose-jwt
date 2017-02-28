/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;


/**
 * Elliptic Curve Diffie-Hellman key agreement functions and utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-02-28
 */
class ECDH {


	/**
	 * Enumeration of the Elliptic Curve Diffie-Hellman Ephemeral Static
	 * algorithm modes.
	 */
	public enum AlgorithmMode {

		/**
		 * Direct key agreement mode.
		 */
		DIRECT,


		/**
		 * Key wrapping mode.
		 */
		KW
	}


	/**
	 * Resolves the ECDH algorithm mode.
	 *
	 * @param alg The JWE algorithm. Must be supported and not
	 *            {@code null}.
	 *
	 * @return The algorithm mode.
	 *
	 * @throws JOSEException If the JWE algorithm is not supported.
	 */
	public static AlgorithmMode resolveAlgorithmMode(final JWEAlgorithm alg)
		throws JOSEException {

		if (alg.equals(JWEAlgorithm.ECDH_ES)) {

			return AlgorithmMode.DIRECT;

		} else if (alg.equals(JWEAlgorithm.ECDH_ES_A128KW) ||
			alg.equals(JWEAlgorithm.ECDH_ES_A192KW) ||
			alg.equals(JWEAlgorithm.ECDH_ES_A256KW)) {

			return AlgorithmMode.KW;
		} else {

			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
				alg,
				ECDHCryptoProvider.SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * Returns the bit length of the shared key (derived via concat KDF)
	 * for the specified JWE ECDH algorithm.
	 *
	 * @param alg The JWE ECDH algorithm. Must be supported and not
	 *            {@code null}.
	 * @param enc The encryption method. Must be supported} and not
	 *            {@code null}.
	 *
	 * @return The bit length of the shared key.
	 *
	 * @throws JOSEException If the JWE algorithm or encryption method is
	 *                       not supported.
	 */
	public static int sharedKeyLength(final JWEAlgorithm alg, final EncryptionMethod enc)
		throws JOSEException {

		if (alg.equals(JWEAlgorithm.ECDH_ES)) {

			int length = enc.cekBitLength();

			if (length == 0) {
				throw new JOSEException("Unsupported JWE encryption method " + enc);
			}

			return length;

		} else if (alg.equals(JWEAlgorithm.ECDH_ES_A128KW)) {
			return 128;
		} else if (alg.equals(JWEAlgorithm.ECDH_ES_A192KW)) {
			return  192;
		} else if (alg.equals(JWEAlgorithm.ECDH_ES_A256KW)) {
			return  256;
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
				alg, ECDHCryptoProvider.SUPPORTED_ALGORITHMS));
		}
	}


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


	/**
	 * Derives a shared key (via concat KDF).
	 *
	 * @param header    The JWE header. Its algorithm and encryption method
	 *                  must be supported. Must not be {@code null}.
	 * @param Z         The derived shared secret ('Z'). Must not be
	 *                  {@code null}.
	 * @param concatKDF The concat KDF. Must be initialised and not
	 *                  {@code null}.
	 *
	 * @return The derived shared key.
	 *
	 * @throws JOSEException If derivation of the shared key failed.
	 */
	public static SecretKey deriveSharedKey(final JWEHeader header,
						final SecretKey Z,
						final ConcatKDF concatKDF)
		throws JOSEException {

		final int sharedKeyLength = sharedKeyLength(header.getAlgorithm(), header.getEncryptionMethod());

		// Set the alg ID for the concat KDF
		AlgorithmMode algMode = resolveAlgorithmMode(header.getAlgorithm());

		final String algID;

		if (algMode == AlgorithmMode.DIRECT) {
			// algID = enc
			algID = header.getEncryptionMethod().getName();
		} else if (algMode == AlgorithmMode.KW) {
			// algID = alg
			algID = header.getAlgorithm().getName();
		} else {
			throw new JOSEException("Unsupported JWE ECDH algorithm mode: " + algMode);
		}

		return concatKDF.deriveKey(
			Z,
			sharedKeyLength,
			ConcatKDF.encodeDataWithLength(algID.getBytes(Charset.forName("ASCII"))),
			ConcatKDF.encodeDataWithLength(header.getAgreementPartyUInfo()),
			ConcatKDF.encodeDataWithLength(header.getAgreementPartyVInfo()),
			ConcatKDF.encodeIntData(sharedKeyLength),
			ConcatKDF.encodeNoData());
	}
	
	
	/**
	 * Ensures the specified ephemeral public key is on the curve of the
	 * private key. Intended to prevent an "Invalid Curve Attack",
	 * independent from any JCA provider checks (the SUN provider in Java
	 * 1.8.0_51+ and BouncyCastle have them, other / older provider do
	 * not).
	 *
	 * <p>See https://www.cs.bris.ac.uk/Research/CryptographySecurity/RWC/2017/nguyen.quan.pdf
	 *
	 * @param ephemeralPublicKey The ephemeral public EC key. Must not be
	 *                           {@code null}.
	 * @param privateKey         The private EC key. Must not be
	 *                           {@code null}.
	 *
	 * @throws JOSEException If the ephemeral public key didn't pass the
	 *                       curve check.
	 */
	public static void ensurePointOnCurve(final ECPublicKey ephemeralPublicKey, final ECPrivateKey privateKey)
		throws JOSEException {
		
		// Ensure the following is met:
		// (y^2) mod p = (x^3 + ax + b) mod p
		ECParameterSpec ecParameterSpec = privateKey.getParams();
		EllipticCurve curve = ecParameterSpec.getCurve();
		ECPoint point = ephemeralPublicKey.getW();
		BigInteger x = point.getAffineX();
		BigInteger y = point.getAffineY();
		BigInteger a = curve.getA();
		BigInteger b = curve.getB();
		BigInteger p = ((ECFieldFp) curve.getField()).getP();
		BigInteger leftSide = (y.pow(2)).mod(p);
		BigInteger rightSide = (x.pow(3).add(a.multiply(x)).add(b)).mod(p);
		
		if (! leftSide.equals(rightSide)) {
			throw new JOSEException("Invalid ephemeral public key: Point not on expected curve");
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private ECDH() {

	}
}
