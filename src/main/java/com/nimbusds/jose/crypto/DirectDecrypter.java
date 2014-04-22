package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;
import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
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
 * registered JWE header parameters}. Use {@link #setAcceptedAlgorithms} and
 * {@link #setAcceptedEncryptionMethods} to restrict the acceptable JWE
 * algorithms and encryption methods.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-22)
 */
public class DirectDecrypter extends DirectCryptoProvider implements JWEDecrypter {


	/**
	 * The accepted JWE algorithms.
	 */
	private Set<JWEAlgorithm> acceptedAlgs =
		new HashSet<JWEAlgorithm>(supportedAlgorithms());


	/**
	 * The accepted encryption methods.
	 */
	private Set<EncryptionMethod> acceptedEncs =
		new HashSet<EncryptionMethod>(supportedEncryptionMethods());


	/**
	 * The critical header parameter checker.
	 */
	private final CriticalHeaderParameterChecker critParamChecker =
		new CriticalHeaderParameterChecker();


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
	}


	@Override
	public Set<JWEAlgorithm> getAcceptedAlgorithms() {

		return acceptedAlgs;
	}


	@Override
	public void setAcceptedAlgorithms(final Set<JWEAlgorithm> acceptedAlgs) {

		if (acceptedAlgs == null) {
			throw new IllegalArgumentException("The accepted JWE algorithms must not be null");
		}

		if (! supportedAlgorithms().containsAll(acceptedAlgs)) {
			throw new IllegalArgumentException("Unsupported JWE algorithm(s)");
		}

		this.acceptedAlgs = acceptedAlgs;
	}


	@Override
	public Set<EncryptionMethod> getAcceptedEncryptionMethods() {

		return acceptedEncs;
	}


	@Override
	public void setAcceptedEncryptionMethods(final Set<EncryptionMethod> acceptedEncs) {

		if (acceptedEncs == null)
			throw new IllegalArgumentException("The accepted encryption methods must not be null");

		if (!supportedEncryptionMethods().containsAll(acceptedEncs)) {
			throw new IllegalArgumentException("Unsupported encryption method(s)");
		}

		this.acceptedEncs = acceptedEncs;
	}


	@Override
	public Set<String> getIgnoredCriticalHeaderParameters() {

		return critParamChecker.getIgnoredCriticalHeaders();
	}


	@Override
	public void setIgnoredCriticalHeaderParameters(final Set<String> headers) {

		critParamChecker.setIgnoredCriticalHeaders(headers);
	}


	@Override
	public byte[] decrypt(final ReadOnlyJWEHeader header,
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
		

		JWEAlgorithm alg = header.getAlgorithm();

		if (! alg.equals(JWEAlgorithm.DIR)) {

			throw new JOSEException("Unsupported algorithm, must be \"dir\"");
		}

		if (! critParamChecker.headerPasses(header)) {

			throw new JOSEException("Unsupported critical header parameter");
		}

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(header.toBase64URL().toString());

		// Decrypt the cipher text according to the JWE enc
		EncryptionMethod enc = header.getEncryptionMethod();

		byte[] plainText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) || enc.equals(EncryptionMethod.A192CBC_HS384) || enc.equals(EncryptionMethod.A256CBC_HS512)) {

			plainText = AESCBC.decryptAuthenticated(getKey(), iv.decode(), cipherText.decode(), aad, authTag.decode(), contentEncryptionProvider, macProvider);

		} else if (enc.equals(EncryptionMethod.A128GCM) || enc.equals(EncryptionMethod.A192GCM) || enc.equals(EncryptionMethod.A256GCM)) {

			plainText = AESGCM.decrypt(getKey(), iv.decode(), cipherText.decode(), aad, authTag.decode(), contentEncryptionProvider);

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A128GCM");
		}


		// Apply decompression if requested
		return DeflateHelper.applyDecompression(header, plainText);
	}
}

