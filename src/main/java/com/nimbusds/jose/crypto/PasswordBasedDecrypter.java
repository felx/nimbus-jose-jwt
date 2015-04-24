package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.Set;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StringUtils;


/**
 * Password-based decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}.
 * This class is thread-safe.
 *
 * <p>Supports the following JSON Web Algorithm (JWA):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS256_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS384_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS512_A256KW}
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-24)
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

		if (!critPolicy.headerPasses(header)) {
			throw new JOSEException("Unsupported JWE algorithm, must be PBES2-HS256+A128KW, PBES2-HS384+A192KW or PBES2-HS512+A256KW");
		}

		final JWEAlgorithm alg = header.getAlgorithm();
		final byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);
		final PRFParams prfParams = getPRFParams(alg);
		final SecretKey psKey = PBKDF2.deriveKey(getPassword(), formattedSalt, iterationCount, prfParams);

		final SecretKey cek = AESKW.decryptCEK(psKey, encryptedKey.decode());

		// Compose the AAD
		byte[] aad = StringUtils.toByteArray(header.toBase64URL().toString());

		// Decrypt the cipher text according to the JWE enc
		EncryptionMethod enc = header.getEncryptionMethod();

		byte[] plainText;

		if (enc.equals(EncryptionMethod.A128CBC_HS256) ||
			enc.equals(EncryptionMethod.A192CBC_HS384) ||
			enc.equals(EncryptionMethod.A256CBC_HS512)) {

			plainText = AESCBC.decryptAuthenticated(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				getJWEJCAProvider().getContentEncryptionProvider(),
				getJWEJCAProvider().getMACProvider());

		} else if (enc.equals(EncryptionMethod.A128GCM) ||
			enc.equals(EncryptionMethod.A192GCM) ||
			enc.equals(EncryptionMethod.A256GCM)) {

			plainText = AESGCM.decrypt(
				cek,
				iv.decode(),
				cipherText.decode(),
				aad,
				authTag.decode(),
				getJWEJCAProvider().getContentEncryptionProvider());

		} else if (enc.equals(EncryptionMethod.A128CBC_HS256_DEPRECATED) ||
			enc.equals(EncryptionMethod.A256CBC_HS512_DEPRECATED)) {

			plainText = AESCBC.decryptWithConcatKDF(
				header,
				cek,
				encryptedKey,
				iv,
				cipherText,
				authTag,
				getJWEJCAProvider().getContentEncryptionProvider(),
				getJWEJCAProvider().getMACProvider());

		} else {

			throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
		}

		// Apply decompression if requested
		return DeflateHelper.applyDecompression(header, plainText);
	}
}
