package com.nimbusds.jose.crypto;


import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * Direct decrypter of {@link com.nimbusds.jose.JWEObject JWE objects} with a
 * shared symmetric key. This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#DIR}
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
 * @version $version$ (2015-06-29)
 */
@ThreadSafe
public class DirectDecrypter extends DirectCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new direct decrypter.
	 *
	 * @param key The symmetric key. Its algorithm must be "AES". Must be
	 *            128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32
	 *            bytes), 384 bits (48 bytes) or 512 bits (64 bytes) long.
	 *            Must not be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public DirectDecrypter(final SecretKey key)
		throws KeyLengthException {

		super(key);
	}


	/**
	 * Creates a new direct decrypter.
	 *
	 * @param keyBytes The symmetric key, as a byte array. Must be 128 bits
	 *                 (16 bytes), 192 bits (24 bytes), 256 bits (32
	 *                 bytes), 384 bits (48 bytes) or 512 bits (64 bytes)
	 *                 long. Must not be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public DirectDecrypter(final byte[] keyBytes)
		throws KeyLengthException {

		this(new SecretKeySpec(keyBytes, "AES"));
	}


	/**
	 * Creates a new direct decrypter.
	 *
	 * @param octJWK The symmetric key, as a JWK. Must be 128 bits (16
	 *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
	 *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
	 *               be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public DirectDecrypter(final OctetSequenceKey octJWK)
		throws KeyLengthException {

		this(octJWK.toSecretKey("AES"));
	}


	/**
	 * Creates a new direct decrypter.
	 *
	 * @param key            The symmetric key. Its algorithm must be
	 *                       "AES". Must be 128 bits (16 bytes), 192 bits
	 *                       (24 bytes), 256 bits (32 bytes), 384 bits (48
	 *                       bytes) or 512 bits (64 bytes) long. Must not
	 *                       be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public DirectDecrypter(final SecretKey key, final Set<String> defCritHeaders)
		throws KeyLengthException {

		super(key);

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
		if (encryptedKey != null) {
			throw new JOSEException("Unexpected present JWE encrypted key");
		}	

		if (iv == null) {
			throw new JOSEException("Unexpected present JWE initialization vector (IV)");
		}

		if (authTag == null) {
			throw new JOSEException("Missing JWE authentication tag");
		}
		

		JWEAlgorithm alg = header.getAlgorithm();

		if (! alg.equals(JWEAlgorithm.DIR)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
		}

		critPolicy.ensureHeaderPasses(header);

		return ContentCryptoProvider.decrypt(header, null, iv, cipherText, authTag, getKey(), getJCAContext());
	}
}

