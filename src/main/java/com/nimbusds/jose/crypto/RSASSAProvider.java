package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for RSA signers and verifiers of {@link
 * com.nimbusds.jose.JWSObject JWS objects}.
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
 * @version $version$ (2015-05-31)
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
}

