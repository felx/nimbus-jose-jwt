package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for RSA Signature-Scheme-with-Appendix (RSASSA) 
 * signers and verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
abstract class RSASSAProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * Initialises the supported algorithms.
	 */
	static {

		Set<JWSAlgorithm> algs = new HashSet<JWSAlgorithm>();
		algs.add(JWSAlgorithm.RS256);
		algs.add(JWSAlgorithm.RS384);
		algs.add(JWSAlgorithm.RS512);

		SUPPORTED_ALGORITHMS = algs;
	}


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) provider.
	 */
	protected RSASSAProvider() {

		super(SUPPORTED_ALGORITHMS);
	}


	/**
	 * Gets an RSA signer and verifier for the specified RSASSA-based JSON Web
	 * Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return An RSA signer and verifier instance.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	protected static Signature getRSASignerAndVerifier(final JWSAlgorithm alg)
			throws JOSEException {

		// The internal crypto provider uses different alg names

		String internalAlgName = null;

		if (alg.equals(JWSAlgorithm.RS256)) {
			internalAlgName = "SHA256withRSA";
		} else if (alg.equals(JWSAlgorithm.RS384)) {
			internalAlgName = "SHA384withRSA";
		} else if (alg.equals(JWSAlgorithm.RS512)) {
			internalAlgName = "SHA512withRSA";
		} else {
			throw new JOSEException("Unsupported RSASSA algorithm, must be RS256, RS384 or RS512");
		}

		try {
			return Signature.getInstance(internalAlgName);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException("Unsupported RSASSA algorithm: " + e.getMessage(), e);
		}
	}
}

