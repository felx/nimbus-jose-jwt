package com.nimbusds.jose.crypto;


import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;


/**
 * Direct encrypter of {@link com.nimbusds.jose.JWEObject JWE objects} with a
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
 * @version 2014-06-29
 */
@ThreadSafe
public class DirectEncrypter extends DirectCryptoProvider implements JWEEncrypter {


	/**
	 * Creates a new direct encrypter.
	 *
	 * @param key The symmetric key. Its algorithm must be "AES". Must be
	 *            128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32
	 *            bytes), 384 bits (48 bytes) or 512 bits (64 bytes) long.
	 *            Must not be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public DirectEncrypter(final SecretKey key)
		throws KeyLengthException {

		super(key);
	}


	/**
	 * Creates a new direct encrypter.
	 *
	 * @param keyBytes The symmetric key, as a byte array. Must be 128 bits
	 *                 (16 bytes), 192 bits (24 bytes), 256 bits (32
	 *                 bytes), 384 bits (48 bytes) or 512 bits (64 bytes)
	 *                 long. Must not be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public DirectEncrypter(final byte[] keyBytes)
		throws KeyLengthException {

		this(new SecretKeySpec(keyBytes, "AES"));
	}


	/**
	 * Creates a new direct encrypter.
	 *
	 * @param octJWK The symmetric key, as a JWK. Must be 128 bits (16
	 *               bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
	 *               bits (48 bytes) or 512 bits (64 bytes) long. Must not
	 *               be {@code null}.
	 *
	 * @throws KeyLengthException If the symmetric key length is not
	 *                            compatible.
	 */
	public DirectEncrypter(final OctetSequenceKey octJWK)
		throws KeyLengthException {

		this(octJWK.toSecretKey("AES"));
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		JWEAlgorithm alg = header.getAlgorithm();

		if (! alg.equals(JWEAlgorithm.DIR)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
		}

		// Check key length matches encryption method
		EncryptionMethod enc = header.getEncryptionMethod();

		if (enc.cekBitLength() != ByteUtils.bitLength(getKey().getEncoded())) {
			throw new KeyLengthException(enc.cekBitLength(), enc);
		}

		final Base64URL encryptedKey = null; // The second JWE part

		return ContentCryptoProvider.encrypt(header, clearText, getKey(), encryptedKey, getJCAContext());
	}
}