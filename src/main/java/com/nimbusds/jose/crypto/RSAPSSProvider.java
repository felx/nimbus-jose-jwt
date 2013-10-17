package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for RSA Signature-Scheme-with-Appendix with PSS
 * encoding (RSASSA-PSS) signers and verifiers of
 * {@link com.nimbusds.jose.JWSObject JWS objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS512}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-17)
 */
public class RSAPSSProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * Initialises the supported algorithms.
	 */
	static {

		Set<JWSAlgorithm> algs = new HashSet<JWSAlgorithm>();
		algs.add(JWSAlgorithm.PS256);
		algs.add(JWSAlgorithm.PS384);
		algs.add(JWSAlgorithm.PS512);

		SUPPORTED_ALGORITHMS = algs;
	}


	/**
	 * Creates a new RSASSA-PSS provider.
	 */
	protected RSAPSSProvider() {

		super(SUPPORTED_ALGORITHMS);
	}


	/**
	 * Gets a signer and verifier for the specified RSASSA-PSS-based JSON
	 * Web Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return A signer and verifier instance.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	protected static Signature getRSASignerAndVerifier(final JWSAlgorithm alg)
		throws JOSEException {

		// The JCE crypto provider uses different alg names

		String internalAlgName;

		if (alg.equals(JWSAlgorithm.PS256)) {

			internalAlgName = "SHA256withRSAandMGF1";

		} else if (alg.equals(JWSAlgorithm.PS384)) {

			internalAlgName = "SHA384withRSAandMGF1";

		} else if (alg.equals(JWSAlgorithm.PS512)) {

			internalAlgName = "SHA512withRSAandMGF1";

		} else {

			throw new JOSEException("Unsupported RSASSA-PSS algorithm, must be PS256, PS384 or PS512");
		}

		try {
			return Signature.getInstance(internalAlgName);

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException("Unsupported RSASSA-PSS algorithm: " + e.getMessage(), e);
		}
	}
}
