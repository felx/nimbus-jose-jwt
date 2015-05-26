package com.nimbusds.jose.crypto;


import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for RSA Signature-Scheme-with-Appendix (RSASSA) 
 * signers and verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS512}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
abstract class RSASSAProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms by the RSA-SSA provider class.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	static {
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWSAlgorithm.RS256);
		algs.add(JWSAlgorithm.RS384);
		algs.add(JWSAlgorithm.RS512);
		algs.add(JWSAlgorithm.PS256);
		algs.add(JWSAlgorithm.PS384);
		algs.add(JWSAlgorithm.PS512);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * Creates a new RSASSA provider.
	 */
	protected RSASSAProvider() {

		super(SUPPORTED_ALGORITHMS);
	}


	/**
	 * Gets a signer and verifier for the specified RSASSA-based JSON Web
	 * Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return A signer and verifier instance.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	protected static Signature getRSASignerAndVerifier(final JWSAlgorithm alg,
							   final Provider provider)
		throws JOSEException {

		// The JCE crypto provider uses different alg names

		final String internalAlgName;

		PSSParameterSpec pssSpec = null;

		if (alg.equals(JWSAlgorithm.RS256)) {

			internalAlgName = "SHA256withRSA";

		} else if (alg.equals(JWSAlgorithm.RS384)) {

			internalAlgName = "SHA384withRSA";

		} else if (alg.equals(JWSAlgorithm.RS512)) {

			internalAlgName = "SHA512withRSA";

		} else if (alg.equals(JWSAlgorithm.PS256)) {

			internalAlgName = "SHA256withRSAandMGF1";

			// JWA mandates salt length must equal hash
			pssSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

		} else if (alg.equals(JWSAlgorithm.PS384)) {

			internalAlgName = "SHA384withRSAandMGF1";

			// JWA mandates salt length must equal hash
			pssSpec = new PSSParameterSpec("SHA384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);

		} else if (alg.equals(JWSAlgorithm.PS512)) {

			internalAlgName = "SHA512withRSAandMGF1";

			// JWA mandates salt length must equal hash
			pssSpec = new PSSParameterSpec("SHA512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);

		} else {
			
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, SUPPORTED_ALGORITHMS));
		}

		final Signature signature;

		try {
			if (provider != null) {
				signature = Signature.getInstance(internalAlgName, provider);
			} else {
				signature = Signature.getInstance(internalAlgName);
			}

		} catch (NoSuchAlgorithmException e) {

			throw new JOSEException("Unsupported RSASSA algorithm: " + e.getMessage(), e);
		}


		if (pssSpec != null) {

			try {
				signature.setParameter(pssSpec);

			} catch (InvalidAlgorithmParameterException e) {

				throw new JOSEException("Invalid RSASSA-PSS salt length parameter: " + e.getMessage(), e);
			}
		}


		return signature;
	}
}

