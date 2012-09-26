package com.nimbusds.jose.crypto;


import org.bouncycastle.asn1.x9.X9ECParameters;

import org.bouncycastle.crypto.Digest;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) setup parameters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
 */
class ECDSAParameters {


	/**
	 * The X9 EC parameters.
	 */
	private final X9ECParameters x9ECParams;


	/**
	 * The digest method.
	 */
	private final Digest digest;


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * setup parameters instance.
	 *
	 * @param x9ECParams The X9 EC parameters.
	 * @param digest     The digest method.
	 */
	public ECDSAParameters(final X9ECParameters x9ECParams, Digest digest) {

		this.x9ECParams = x9ECParams;
		this.digest = digest;
	}


	/**
	 * Gets the X9 EC parameters.
	 *
	 * @return The X9 EC parameters.
	 */
	public X9ECParameters getX9ECParameters() {

		return x9ECParams;
	}


	/**
	 * Gets the digest method.
	 *
	 * @return The digest method.
	 */
	public Digest getDigest() {

		return digest;
	}
}
