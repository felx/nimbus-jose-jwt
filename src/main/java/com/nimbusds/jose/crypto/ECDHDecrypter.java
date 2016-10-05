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


import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * Elliptic Curve Diffie-Hellman decrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects}. Expects a private EC key
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
 *     <li>{@link com.nimbusds.jose.jwk.ECKey.Curve#P_256}
 *     <li>{@link com.nimbusds.jose.jwk.ECKey.Curve#P_384}
 *     <li>{@link com.nimbusds.jose.jwk.ECKey.Curve#P_521}
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
public class ECDHDecrypter extends ECDHCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The private EC key.
	 */
	private final ECPrivateKey privateKey;


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman decrypter.
	 *
	 * @param privateKey The private EC key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve is not supported.
	 */
	public ECDHDecrypter(final ECPrivateKey privateKey)
		throws JOSEException {

		this(privateKey, null);
	}


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman decrypter.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must contain a private
	 *              part. Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve is not supported.
	 */
	public ECDHDecrypter(final ECKey ecJWK)
		throws JOSEException {

		super(ecJWK.getCurve());

		if (! ecJWK.isPrivate()) {
			throw new JOSEException("The EC JWK doesn't contain a private part");
		}

		this.privateKey = ecJWK.toECPrivateKey();
	}


	/**
	 * Creates a new Elliptic Curve Diffie-Hellman decrypter.
	 *
	 * @param privateKey     The private EC key. Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 *
	 * @throws JOSEException If the elliptic curve is not supported.
	 */
	public ECDHDecrypter(final ECPrivateKey privateKey, final Set<String> defCritHeaders)
		throws JOSEException {

		super(ECKey.Curve.forECParameterSpec(privateKey.getParams()));

		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);

		this.privateKey = privateKey;
	}


	/**
	 * Returns the private EC key.
	 *
	 * @return The private EC key.
	 */
	public ECPrivateKey getPrivateKey() {

		return privateKey;
	}


	@Override
	public Set<String> getProcessedCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public Set<String> getDeferredCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public byte[] decrypt(final JWEHeader header,
			      final Base64URL encryptedKey,
			      final Base64URL iv,
			      final Base64URL cipherText,
			      final Base64URL authTag)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final ECDH.AlgorithmMode algMode = ECDH.resolveAlgorithmMode(alg);

		critPolicy.ensureHeaderPasses(header);

		// Get ephemeral EC key
		ECKey ephemeralKey = header.getEphemeralPublicKey();

		if (ephemeralKey == null) {
			throw new JOSEException("Missing ephemeral public EC key \"epk\" JWE header parameter");
		}

		ECPublicKey ephemeralPublicKey = ephemeralKey.toECPublicKey();

		// Derive 'Z'
		SecretKey Z = ECDH.deriveSharedSecret(
			ephemeralPublicKey,
			privateKey,
			getJCAContext().getKeyEncryptionProvider());

		// Derive shared key via concat KDF
		getConcatKDF().getJCAContext().setProvider(getJCAContext().getMACProvider()); // update before concat
		SecretKey sharedKey = ECDH.deriveSharedKey(header, Z, getConcatKDF());

		final SecretKey cek;

		if (algMode.equals(ECDH.AlgorithmMode.DIRECT)) {
			cek = sharedKey;
		} else if (algMode.equals(ECDH.AlgorithmMode.KW)) {
			if (encryptedKey == null) {
				throw new JOSEException("Missing JWE encrypted key");
			}
			cek = AESKW.unwrapCEK(sharedKey, encryptedKey.decode(), getJCAContext().getKeyEncryptionProvider());
		} else {
			throw new JOSEException("Unexpected JWE ECDH algorithm mode: " + algMode);
		}

		return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
	}
}
