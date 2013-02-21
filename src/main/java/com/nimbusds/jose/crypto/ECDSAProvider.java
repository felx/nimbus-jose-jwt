package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * The base abstract class for Elliptic Curve Digital Signature Algorithm 
 * (ECDSA) signers and validators of {@link com.nimbusds.jose.JWSObject JWS 
 * objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES512}
 * </ul>
 * 
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-09)
 */
abstract class ECDSAProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * Initialises the supported algorithms.
	 */
	static {

		Set<JWSAlgorithm> algs = new HashSet<JWSAlgorithm>();
		algs.add(JWSAlgorithm.ES256);
		algs.add(JWSAlgorithm.ES384);
		algs.add(JWSAlgorithm.ES512);

		SUPPORTED_ALGORITHMS = algs;
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * provider.
	 */
	protected ECDSAProvider() {

		super(SUPPORTED_ALGORITHMS);
	}


	/**
	 * Gets the initial parameters for the specified ECDSA-based JSON Web 
	 * Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return The initial ECDSA parameters.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	protected static ECDSAParameters getECDSAParameters(final JWSAlgorithm alg)
			throws JOSEException {

		ASN1ObjectIdentifier oid = null;
		Digest digest = null;

		if (alg.equals(JWSAlgorithm.ES256)) {

			oid = SECObjectIdentifiers.secp256r1;
			digest = new SHA256Digest();
		}
		else if (alg.equals(JWSAlgorithm.ES384)) {

			oid = SECObjectIdentifiers.secp384r1;
			digest = new SHA384Digest();
		}
		else if (alg.equals(JWSAlgorithm.ES512)) {

			oid = SECObjectIdentifiers.secp521r1;
			digest = new SHA512Digest();
		}
		else {
			throw new JOSEException("Unsupported ECDSA algorithm, must be ES256, ES384 or ES512");
		}

		X9ECParameters x9ECParams = SECNamedCurves.getByOID(oid);

		return new ECDSAParameters(x9ECParams, digest);
	}
}

