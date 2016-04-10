package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.Set;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.base64.Base64URL;


/**
 * Password-based decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}.
 * This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS256_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS384_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS512_A256KW}
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
 * @version 2015-06-07
 */
@ThreadSafe
public class PasswordBasedDecrypter extends PasswordBasedCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new password-based decrypter.
	 *
	 * @param password The password bytes. Must not be empty or
	 *                 {@code null}.
	 */
	public PasswordBasedDecrypter(final byte[] password) {

		super(password);
	}


	/**
	 * Creates a new password-based decrypter.
	 *
	 * @param password The password, as a UTF-8 encoded string. Must not be
	 *                 empty or {@code null}.
	 */
	public PasswordBasedDecrypter(final String password) {

		super(password.getBytes(Charset.forName("UTF-8")));
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

		if (header.getPBES2Salt() == null) {
			throw new JOSEException("Missing JWE \"p2s\" header parameter");
		}

		final byte[] salt = header.getPBES2Salt().decode();

		if (header.getPBES2Count() < 1) {
			throw new JOSEException("Missing JWE \"p2c\" header parameter");
		}

		final int iterationCount = header.getPBES2Count();

		critPolicy.ensureHeaderPasses(header);

		final JWEAlgorithm alg = header.getAlgorithm();
		final byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);
		final PRFParams prfParams = PRFParams.resolve(alg, getJCAContext().getMACProvider());
		final SecretKey psKey = PBKDF2.deriveKey(getPassword(), formattedSalt, iterationCount, prfParams);

		final SecretKey cek = AESKW.unwrapCEK(psKey, encryptedKey.decode(), getJCAContext().getKeyEncryptionProvider());

		return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
	}
}
