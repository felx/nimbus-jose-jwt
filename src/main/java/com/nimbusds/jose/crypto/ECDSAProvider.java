package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for Elliptic Curve Digital Signature Algorithm 
 * (ECDSA) signers and validators of {@link com.nimbusds.jose.JWSObject JWS 
 * objects}.
 *
 * <p>Supports the following EC-based JWS algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES512}
 * </ul>
 * 
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
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
	 */
	protected ECDSAProvider() {

		super(SUPPORTED_ALGORITHMS);
	}
}

