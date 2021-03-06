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


import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;


/**
 * Elliptic Curve Diffie-Hellman encrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects}. Expects a public EC key
 * (with a P-256, P-384 or P-521 curve).
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.6">section 4.6</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_ES_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_256}
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_384}
 *     <li>{@link com.nimbusds.jose.jwk.Curve#P_521}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
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
 * @author Vladimir Dzhuvinov
 * @version 2015-06-08
 */
@ThreadSafe
public class ECDHEncrypter extends ECDHCryptoProvider implements JWEEncrypter {


	/**
	 * The public EC key.
	 */
	private final ECPublicKey publicKey;


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman encrypter.
	 *
	 * @param publicKey The public EC key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve is not supported.
	 */
	public ECDHEncrypter(final ECPublicKey publicKey)
		throws JOSEException {

		super(Curve.forECParameterSpec(publicKey.getParams()));

		this.publicKey = publicKey;
	}


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman encrypter.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve is not supported.
	 */
	public ECDHEncrypter(final ECKey ecJWK)
		throws JOSEException {

		super(ecJWK.getCurve());

		publicKey = ecJWK.toECPublicKey();
	}


	/**
	 * Returns the public EC key.
	 *
	 * @return The public EC key.
	 */
	public ECPublicKey getPublicKey() {

		return publicKey;
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final ECDH.AlgorithmMode algMode = ECDH.resolveAlgorithmMode(alg);
		final EncryptionMethod enc = header.getEncryptionMethod();

		// Generate ephemeral EC key pair on the same curve as the consumer's public key
		KeyPair ephemeralKeyPair = generateEphemeralKeyPair(publicKey.getParams());
		ECPublicKey ephemeralPublicKey = (ECPublicKey)ephemeralKeyPair.getPublic();
		ECPrivateKey ephemeralPrivateKey = (ECPrivateKey)ephemeralKeyPair.getPrivate();

		// Derive 'Z'
		SecretKey Z = ECDH.deriveSharedSecret(
			publicKey,
			ephemeralPrivateKey,
			getJCAContext().getKeyEncryptionProvider());

		// Derive shared key via concat KDF
		getConcatKDF().getJCAContext().setProvider(getJCAContext().getMACProvider()); // update before concat
		SecretKey sharedKey = ECDH.deriveSharedKey(header, Z, getConcatKDF());

		final SecretKey cek;
		final Base64URL encryptedKey; // The CEK encrypted (second JWE part)

		if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {
			cek = sharedKey;
			encryptedKey = null;
		} else if (algMode.equals(ECDH.AlgorithmMode.KW)) {
			cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());
			encryptedKey = Base64URL.encode(AESKW.wrapCEK(cek, sharedKey, getJCAContext().getKeyEncryptionProvider()));
		} else {
			throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
		}

		// Add the ephemeral public EC key to the header
		JWEHeader updatedHeader = new JWEHeader.Builder(header).
			ephemeralPublicKey(new ECKey.Builder(getCurve(), ephemeralPublicKey).build()).
			build();

		return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJCAContext());
	}


	/**
	 * Generates a new ephemeral EC key pair with the specified curve.
	 *
	 * @param ecParameterSpec The EC key spec. Must not be {@code null}.
	 *
	 * @return The EC key pair.
	 *
	 * @throws JOSEException If the EC key pair couldn't be generated.
	 */
	private KeyPair generateEphemeralKeyPair(final ECParameterSpec ecParameterSpec)
		throws JOSEException {

		Provider keProvider = getJCAContext().getKeyEncryptionProvider();

		try {
			KeyPairGenerator generator;

			if (keProvider != null) {
				generator = KeyPairGenerator.getInstance("EC", keProvider);
			} else {
				generator = KeyPairGenerator.getInstance("EC");
			}

			generator.initialize(ecParameterSpec);
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new JOSEException("Couldn't generate ephemeral EC key pair: " + e.getMessage(), e);
		}
	}
}
