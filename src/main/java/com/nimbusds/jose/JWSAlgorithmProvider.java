package com.nimbusds.jose;


import java.util.Set;


/**
 * Common interface for JSON Web Signature (JWS) {@link JWSSigner signers} and
 * {@link JWSVerifier verifiers}.
 *
 * <p>Callers can query the JWS provider to determine its algorithm 
 * capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2015-04-17)
 */
public interface JWSAlgorithmProvider extends AlgorithmProvider {


	/**
	 * Returns the names of the supported JWS algorithms. These correspond
	 * to the {@code alg} JWS header parameter.
	 *
	 * @return The supported JWS algorithms, empty set if none.
	 */
	public Set<JWSAlgorithm> supportedAlgorithms();


	/**
	 * Returns the JCA provider specification.
	 *
	 * @return The JCA provider specification, {@code null} if not
	 *         specified.
	 */
	public JWSJCAProviderSpec getJCAProviderSpec();
}
