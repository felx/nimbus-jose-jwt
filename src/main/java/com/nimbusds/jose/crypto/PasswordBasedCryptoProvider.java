package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;


/**
 * The base abstract class for password-based encrypters and decrypters of
 * {@link com.nimbusds.jose.JWEObject JWE objects}.
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
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-24)
 */
abstract class PasswordBasedCryptoProvider extends BaseJWEProvider {


	/**
	 * The supported JWE algorithms.
	 */
	public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported encryption methods.
	 */
	public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


	/**
	 * Initialises the supported algorithms and encryption methods.
	 */
	static {
		Set<JWEAlgorithm> algs = new HashSet<>();
		algs.add(JWEAlgorithm.PBES2_HS256_A128KW);
		algs.add(JWEAlgorithm.PBES2_HS384_A192KW);
		algs.add(JWEAlgorithm.PBES2_HS512_A256KW);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

		Set<EncryptionMethod> methods = new HashSet<>();
		methods.add(EncryptionMethod.A128CBC_HS256);
		methods.add(EncryptionMethod.A192CBC_HS384);
		methods.add(EncryptionMethod.A256CBC_HS512);
		methods.add(EncryptionMethod.A128GCM);
		methods.add(EncryptionMethod.A192GCM);
		methods.add(EncryptionMethod.A256GCM);
		methods.add(EncryptionMethod.A128CBC_HS256_DEPRECATED);
		methods.add(EncryptionMethod.A256CBC_HS512_DEPRECATED);
		SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(methods);
	}


	/**
	 * Gets the Pseudo-Random Function (PRF) parameters for the specified
	 * PBES2 JWE algorithm.
	 *
	 * @param alg The JWE algorithm. Must be supported and not
	 *            {@code null}.
	 *
	 * @return The PRF parameters.
	 *
	 * @throws JOSEException If the JWE algorithm is not supported.
	 */
	protected PRFParams getPRFParams(final JWEAlgorithm alg)
		throws JOSEException {

		final String jcaMagAlg;
		final int dkLen;

		if (JWEAlgorithm.PBES2_HS256_A128KW.equals(alg)) {
			jcaMagAlg = "HmacSHA256";
			dkLen = 16;
		} else if (JWEAlgorithm.PBES2_HS384_A192KW.equals(alg)) {
			jcaMagAlg = "HmacSHA384";
			dkLen = 24;
		} else if (JWEAlgorithm.PBES2_HS512_A256KW.equals(alg)) {
			jcaMagAlg = "HmacSHA512";
			dkLen = 32;
		} else {
			throw new JOSEException("Unsupported JWE algorithm, must be PBES2-HS256+A128KW, PBES2-HS384+A192KW or PBES2-HS512+A256KW");
		}

		return new PRFParams(jcaMagAlg, getJWEJCAProvider().getMACProvider(), dkLen);
	}


	/**
	 * The password.
	 */
	private final byte[] password;


	/**
	 * Creates a new password-based encryption / decryption provider.
	 *
	 * @param password The password bytes. Must not be empty or
	 *                 {@code null}.
	 */
	protected PasswordBasedCryptoProvider(final byte[] password) {

		super(SUPPORTED_ALGORITHMS, SUPPORTED_ENCRYPTION_METHODS);

		if (password == null || password.length == 0) {
			throw new IllegalArgumentException("The password must not be null or empty");
		}

		this.password = password;
	}


	/**
	 * Returns the password.
	 *
	 * @return The password bytes.
	 */
	public byte[] getPassword() {

		return password;
	}


	/**
	 * Returns the password.
	 *
	 * @return The password as a UTF-8 encoded string.
	 */
	public String getPasswordString() {

		return new String(password, Charset.forName("UTF-8"));
	}
}
