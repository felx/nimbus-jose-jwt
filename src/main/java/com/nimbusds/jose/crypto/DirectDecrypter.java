package com.nimbusds.jose.crypto;


import javax.crypto.SecretKey;

import com.nimbusds.jose.DefaultJWEHeaderFilter;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeaderFilter;
import com.nimbusds.jose.ReadOnlyJWEHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;


/**
 * Direct decrypter of {@link com.nimbusds.jose.JWEObject JWE objects} with a
 * shared symmetric key. This class is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#DIR}
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
 * </ul>
 *
 * <p>Accepts all {@link com.nimbusds.jose.JWEHeader#getRegisteredParameterNames
 * registered JWE header parameters}. Modify the {@link #getJWEHeaderFilter
 * header filter} properties to restrict the acceptable JWE algorithms, 
 * encryption methods and header parameters, or to allow custom JWE header 
 * parameters.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-11-25)
 *
 */
public class DirectDecrypter extends DirectCryptoProvider implements JWEDecrypter {


	/**
	 * The JWE header filter.
	 */
	private final DefaultJWEHeaderFilter headerFilter;


	/**
	 * Creates a new direct decrypter.
	 *
	 * @param key The shared symmetric key. Its algorithm must be "AES".
	 *            Must be 128 bits (16 bytes), 256 bits (32 bytes) or 512 
	 *            bits (64 bytes) long. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key length is unexpected.
	 */
	public DirectDecrypter(final SecretKey key)
		throws JOSEException {

		super(key);

		headerFilter = new DefaultJWEHeaderFilter(supportedAlgorithms(), supportedEncryptionMethods());
	}


	/**
	 * Creates a new direct decrypter.
	 *
	 * @param keyBytes The shared symmetric key, as a byte array. Must be 
	 *                 128 bits (16 bytes), 256 bits (32 bytes) or 512 bits
	 *                 (64 bytes) long. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key length is unexpected.
	 */
	public DirectDecrypter(final byte[] keyBytes)
		throws JOSEException {

		super(keyBytes);

		headerFilter = new DefaultJWEHeaderFilter(supportedAlgorithms(), supportedEncryptionMethods());
	}


	@Override
	public JWEHeaderFilter getJWEHeaderFilter() {

		return headerFilter;
	}


	@Override
	public byte[] decrypt(final ReadOnlyJWEHeader readOnlyJWEHeader,
		              final Base64URL encryptedKey,
		              final Base64URL iv,
		              final Base64URL cipherText,
		              final Base64URL authTag) 
		throws JOSEException {

		// Validate required JWE parts
		if (encryptedKey != null) {

			throw new JOSEException("Unexpected encrypted key, must be omitted");
		}	

		if (iv == null) {

			throw new JOSEException("The initialization vector (IV) must not be null");
		}

		if (authTag == null) {

			throw new JOSEException("The authentication tag must not be null");
		}
		

		JWEAlgorithm alg = readOnlyJWEHeader.getAlgorithm();

		if (! alg.equals(JWEAlgorithm.DIR)) {

			throw new JOSEException("Unsupported algorithm, must be \"dir\"");
		}

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(readOnlyJWEHeader.toBase64URL().toString());

		// Decrypt the cipher text according to the JWE enc
		EncryptionMethod enc = readOnlyJWEHeader.getEncryptionMethod();

		byte[] plainText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A192CBC_HS384) || enc.equals(EncryptionMethod.A256CBC_HS512)) {

			plainText = AESCBC.decryptAuthenticated(getKey(), iv.decode(), cipherText.decode(), aad, authTag.decode(), provider);

		} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A192GCM) || enc.equals(EncryptionMethod.A256GCM)) {

			plainText = AESGCM.decrypt(getKey(), iv.decode(), cipherText.decode(), aad, authTag.decode(), provider);

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A128GCM");
		}


		// Apply decompression if requested
		return DeflateHelper.applyDecompression(readOnlyJWEHeader, plainText);
	}
}

