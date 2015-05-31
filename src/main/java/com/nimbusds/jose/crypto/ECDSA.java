package com.nimbusds.jose.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;

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
import static com.nimbusds.jose.jwk.ECKey.Curve;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) functions and utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-05-30)
 */
class ECDSA {


	/**
	 * Resolves the matching EC DSA algorithm for the specified EC key
	 * (public or private).
	 *
	 * @param ecKey The EC key. Must not be {@code null}.
	 *
	 * @return The matching EC DSA algorithm.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public static JWSAlgorithm resolveAlgorithm(final ECKey ecKey)
		throws JOSEException {

		ECParameterSpec ecParameterSpec = ecKey.getParams();
		return resolveAlgorithm(Curve.forECParameterSpec(ecParameterSpec));
	}


	/**
	 * Resolves the matching EC DSA algorithm for the specified elliptic
	 * curve.
	 *
	 * @param curve The elliptic curve. May be {@code null}.
	 *
	 * @return The matching EC DSA algorithm.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public static JWSAlgorithm resolveAlgorithm(final Curve curve)
		throws JOSEException {

		if (curve == null) {
			throw new JOSEException("The EC key curve is not supported, must be P256, P384 or P521");
		} else if (Curve.P_256.equals(curve)) {
			return JWSAlgorithm.ES256;
		} else if (Curve.P_384.equals(curve)) {
			return JWSAlgorithm.ES384;
		} else if (Curve.P_521.equals(curve)) {
			return JWSAlgorithm.ES512;
		} else {
			throw new JOSEException("Unexpected curve: " + curve);
		}
	}


	public static Signature getSignerAndVerifier(final JWSAlgorithm alg,
						     final Provider jcaProvider)
		throws JOSEException {

		String jcaAlg;

		if (alg.equals(JWSAlgorithm.ES256)) {
			jcaAlg = "SHA256withECDSA";
		} else if (alg.equals(JWSAlgorithm.ES384)) {
			jcaAlg = "SHA384withECDSA";
		} else if (alg.equals(JWSAlgorithm.ES512)) {
			jcaAlg = "SHA512withECDSA";
		} else {
			throw new JOSEException(
				AlgorithmSupportMessage.unsupportedJWSAlgorithm(
					alg,
					ECDSAProvider.SUPPORTED_ALGORITHMS));
		}

		try {
			if (jcaProvider != null) {
				return Signature.getInstance(jcaAlg, jcaProvider);
			} else {
				return Signature.getInstance(jcaAlg);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException("Unsupported ECDSA algorithm: " + e.getMessage(), e);
		}
	}


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
