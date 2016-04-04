package com.nimbusds.jose.crypto;


import java.util.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for Elliptic Curve Digital Signature Algorithm 
 * (ECDSA) signers and validators of {@link com.nimbusds.jose.JWSObject JWS 
 * objects}.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES512}
 * </ul>
 * 
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 2015-06-07
 */
abstract class ECDSAProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms by the EC-DSA provider class.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	static {
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWSAlgorithm.ES256);
		algs.add(JWSAlgorithm.ES384);
		algs.add(JWSAlgorithm.ES512);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * provider.
	 *
	 * @param alg The EC-DSA algorithm. Must be supported and not
	 *            {@code null}.
	 *
	 * @throws JOSEException If JWS algorithm is not supported.
	 */
	protected ECDSAProvider(final JWSAlgorithm alg)
		throws JOSEException {

		super(new HashSet<>(Arrays.asList(alg)));

		if (! SUPPORTED_ALGORITHMS.contains(alg)) {
			throw new JOSEException("Unsupported EC DSA algorithm: " + alg);
		}
	}
}

