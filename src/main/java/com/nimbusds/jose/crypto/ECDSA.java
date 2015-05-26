package com.nimbusds.jose.crypto;


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
 * Elliptic Curve Digital Signature Algorithm (ECDSA) functions and utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-26)
 */
class ECDSA {


	/**
	 * Returns the expected signature byte array length (R + S parts) for
	 * the specified ECDSA algorithm.
	 *
	 * @param alg The ECDSA algorithm. Must be supported and not
	 *            {@code null}.
	 *
	 * @return The expected byte array length for the signature.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static int getSignatureByteArrayLength(final JWSAlgorithm alg)
		throws JOSEException {

		if (alg.equals(JWSAlgorithm.ES256)) {

			return 64;

		} else if (alg.equals(JWSAlgorithm.ES384)) {

			return 96;

		} else if (alg.equals(JWSAlgorithm.ES512)) {

			return 132;

		} else {

			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
				alg,
				ECDSAProvider.SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * Returns the initial parameters for the specified ECDSA algorithm.
	 *
	 * @param alg The ECDSA algorithm. Must be supported and not
	 *            {@code null}.
	 *
	 * @return The initial ECDSA parameters.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static ECDSAParameters getECDSAParameters(final JWSAlgorithm alg)
		throws JOSEException {

		ASN1ObjectIdentifier oid;
		Digest digest;

		if (alg.equals(JWSAlgorithm.ES256)) {

			oid = SECObjectIdentifiers.secp256r1;
			digest = new SHA256Digest();

		} else if (alg.equals(JWSAlgorithm.ES384)) {

			oid = SECObjectIdentifiers.secp384r1;
			digest = new SHA384Digest();

		} else if (alg.equals(JWSAlgorithm.ES512)) {

			oid = SECObjectIdentifiers.secp521r1;
			digest = new SHA512Digest();

		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
				alg, ECDSAProvider.SUPPORTED_ALGORITHMS));
		}

		X9ECParameters x9ECParams = SECNamedCurves.getByOID(oid);

		return new ECDSAParameters(x9ECParams, digest);
	}


	/**
	 * Prevents public instantiation.
	 */
	private ECDSA() {}
}
