package com.nimbusds.jose.crypto;


import java.util.*;

import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.util.ByteUtils;


/**
 * The base abstract class for direct encrypters and decrypters of
 * {@link com.nimbusds.jose.JWEObject JWE objects} with a shared symmetric key.
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
 * @version $version$ (2015-05-26)
 */
abstract class DirectCryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms by the direct crypto provider class.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported encryption methods by the direct crypto provider
	 * class.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


	static {
		Set<JWEAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWEAlgorithm.DIR);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * Returns the compatible encryption methods for the specified Content
	 * Encryption Key (CEK) length.
	 *
	 * @param cekLength The CEK length in bits.
	 *
	 * @return The compatible encryption methods.
	 *
	 * @throws JOSEException If the CEK length is not compatible.
	 */
	private static Set<EncryptionMethod> getCompatibleEncryptionMethods(final int cekLength)
		throws JOSEException {

		Set<EncryptionMethod> encs = ContentCryptoProvider.COMPATIBLE_ENCRYPTION_METHODS.get(cekLength);

		if (encs == null) {
			throw new JOSEException("The Content Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384 bits (48 bytes) or 512 bites (64 bytes)");
		}

		return encs;
	}


	/**
	 * The Content Encryption Key (CEK).
	 */
	private final SecretKey cek;


	/**
	 * Creates a new direct encryption / decryption provider.
	 *
	 * @param cek The Content Encryption Key (CEK). Must be 128 bits (16
	 *            bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384
	 *            bits (48 bytes) or 512 bits (64 bytes) long. Must not be
	 *            {@code null}.
	 *
	 * @throws JOSEException If the CEK length is not compatible.
	 */
	protected DirectCryptoProvider(final SecretKey cek)
		throws JOSEException {

		super(SUPPORTED_ALGORITHMS, getCompatibleEncryptionMethods(ByteUtils.bitLength(cek.getEncoded())));

		this.cek = cek;
	}


	/**
	 * Gets the Content Encryption Key (CEK).
	 *
	 * @return The key.
	 */
	public SecretKey getKey() {

		return cek;
	}
}
