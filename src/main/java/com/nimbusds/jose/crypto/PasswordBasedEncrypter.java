package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;


/**
 * Password-based encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}.
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
 * @version $version$ (2015-05-16)
 */
@ThreadSafe
public class PasswordBasedEncrypter extends PasswordBasedCryptoProvider implements JWEEncrypter {


	/**
	 * The minimum salt length (8 bytes).
	 */
	public static final int MIN_SALT_LENGTH = 8;


	/**
	 * The cryptographic salt length, in bytes.
	 */
	private final int saltLength;


	/**
	 * The minimum recommended iteration count (1000).
	 */
	public static final int MIN_RECOMMENDED_ITERATION_COUNT = 1000;


	/**
	 * The iteration count.
	 */
	private final int iterationCount;


	/**
	 * Creates a new password-based encrypter.
	 *
	 * @param password       The password bytes. Must not be empty or
	 *                       {@code null}.
	 * @param saltLength     The length of the generated cryptographic
	 *                       salts, in bytes. Must be at least 8 bytes.
	 * @param iterationCount The pseudo-random function (PRF) iteration
	 *                       count. Must be at least 1000.
	 */
	public PasswordBasedEncrypter(final byte[] password,
				      final int saltLength,
				      final int iterationCount) {

		super(password);

		if (saltLength < MIN_SALT_LENGTH) {
			throw new IllegalArgumentException("The minimum salt length (p2s) is " + MIN_SALT_LENGTH + " bytes");
		}

		this.saltLength = saltLength;

		if (iterationCount < MIN_RECOMMENDED_ITERATION_COUNT) {
			throw new IllegalArgumentException("The minimum recommended iteration count (p2c) is " + MIN_RECOMMENDED_ITERATION_COUNT);
		}

		this.iterationCount = iterationCount;
	}


	/**
	 * Creates a new password-based encrypter.
	 *
	 * @param password       The password, as a UTF-8 encoded string. Must
	 *                       not be empty or {@code null}.
	 * @param saltLength     The length of the generated cryptographic
	 *                       salts, in bytes. Must be at least 8 bytes.
	 * @param iterationCount The pseudo-random function (PRF) iteration
	 *                       count. Must be at least 1000.
	 */
	public PasswordBasedEncrypter(final String password,
				      final int saltLength,
				      final int iterationCount) {

		this(password.getBytes(Charset.forName("UTF-8")), saltLength, iterationCount);
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		final JWEAlgorithm alg = header.getAlgorithm();
		final EncryptionMethod enc = header.getEncryptionMethod();

		final byte[] salt = new byte[saltLength];
		getJWEJCAProvider().getSecureRandom().nextBytes(salt);
		final byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);
		final PRFParams prfParams = getPRFParams(alg);
		final SecretKey psKey = PBKDF2.deriveKey(getPassword(), formattedSalt, iterationCount, prfParams);

		// We need to work on the header
		final JWEHeader updatedHeader = new JWEHeader.Builder(header).
			pbes2Salt(Base64URL.encode(salt)).
			pbes2Count(iterationCount).
			build();

		final SecretKey cek = AES.generateKey(enc.cekBitLength(), getJWEJCAProvider().getSecureRandom());

		// The second JWE part
		final Base64URL encryptedKey = Base64URL.encode(AESKW.encryptCEK(cek, psKey));

		return  ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJWEJCAProvider());
	}


	/**
	 * Returns the length of the generated cryptographic salts.
	 *
	 * @return The length of the generated cryptographic salts, in bytes.
	 */
	public int getSaltLength() {

		return saltLength;
	}


	/**
	 * Returns the pseudo-random function (PRF) iteration count.
	 *
	 * @return The iteration count.
	 */
	public int getIterationCount() {

		return iterationCount;
	}
}
