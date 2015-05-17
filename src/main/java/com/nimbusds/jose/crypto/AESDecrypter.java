package com.nimbusds.jose.crypto;


import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * AES decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-16)
 */
@ThreadSafe
public class AESDecrypter extends AESCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new AES decrypter.
	 *
	 * @param kek The Key Encrypting Key. Must be 128 bits (16 bytes), 192
	 *            bits (24 bytes) or 256 bits (32 bytes). Must not be
	 *            {@code null}.
	 */
	public AESDecrypter(final SecretKey kek) {

		this(kek, null);
	}


	/**
	 * Creates a new AES decrypter.
	 *
	 * @param keyBytes The Key Encrypting Key, as a byte array. Must be 128
	 *                 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32
	 *                 bytes). Must not be {@code null}.
	 */
	public AESDecrypter(final byte[] keyBytes)
		throws IllegalArgumentException {

		this(new SecretKeySpec(keyBytes, "AES"));
	}


	/**
	 * Creates a new AES decrypter.
	 *
	 * @param octJWK The Key Encryption Key, as a JWK. Must be 128 bits (16
	 *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
	 *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
	 *               be {@code null}.
	 */
	public AESDecrypter(final OctetSequenceKey octJWK) {

		this(octJWK.toSecretKey("AES"));
	}


	/**
	 * Creates a new AES decrypter.
	 *
	 * @param kek            The Key Encrypting Key. Must be 128 bits (16
	 *                       bytes), 192 bits (24 bytes) or 256 bits (32
	 *                       bytes). Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 */
	public AESDecrypter(final SecretKey kek, final Set<String> defCritHeaders) {

		super(kek);

		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
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

		// Validate required JWE parts
		if (encryptedKey == null) {
			throw new JOSEException("Missing JWE encrypted key");
		}

		if (iv == null) {
			throw new JOSEException("Missing JWE initialization vector (IV)");
		}

		if (authTag == null) {
			throw new JOSEException("Missing JWE authentication tag");
		}

		if (! critPolicy.headerPasses(header)) {
			throw new JOSEException("Unsupported critical header parameter(s)");
		}


		// Derive the content encryption key
		JWEAlgorithm alg = header.getAlgorithm();
		int keyLength = header.getEncryptionMethod().cekBitLength();

		final SecretKey cek;

		if (alg.equals(JWEAlgorithm.A128KW) ||
		    alg.equals(JWEAlgorithm.A192KW) ||
		    alg.equals(JWEAlgorithm.A256KW))   {

			cek = AESKW.decryptCEK(getKey(), encryptedKey.decode());

		} else if (alg.equals(JWEAlgorithm.A128GCMKW) ||
			   alg.equals(JWEAlgorithm.A192GCMKW) ||
			   alg.equals(JWEAlgorithm.A256GCMKW)) {

			byte[] keyIV = header.getIV().decode(); // todo check
			byte[] keyTag = header.getAuthTag().decode(); // todo check
			AuthenticatedCipherText authEncrCEK = new AuthenticatedCipherText(encryptedKey.decode(), keyTag);
			cek = AESGCMKW.decryptCEK(getKey(), keyIV, authEncrCEK, keyLength, getJWEJCAProvider().getKeyEncryptionProvider());

		} else {

			throw new JOSEException("Unsupported JWE algorithm, must be A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW orA256GCMKW");
		}

		return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJWEJCAProvider());
	}
}