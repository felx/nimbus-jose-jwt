package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) verifier of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
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
 * @version $version$ (2015-05-26)
 */
@ThreadSafe
public class ECDSAVerifier extends ECDSAProvider implements JWSVerifier, CriticalHeaderParamsAware {


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * The 'x' EC coordinate.
	 */
	private final BigInteger x;


	/**
	 * The 'y' EC coordinate.
	 */
	private final BigInteger y;



	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * verifier.
	 *
	 * @param x The 'x' coordinate for the elliptic curve point. Must not 
	 *          be {@code null}.
	 * @param y The 'y' coordinate for the elliptic curve point. Must not 
	 *          be {@code null}.
	 */
	public ECDSAVerifier(final BigInteger x, final BigInteger y) {

		this(x, y, null);
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * verifier.
	 *
	 * @param publicKey The public EC key. Must not be {@code null}.
	 */
	public ECDSAVerifier(final ECPublicKey publicKey) {

		this(publicKey.getW().getAffineX(), publicKey.getW().getAffineY());
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * verifier.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must not be {@code null}.
	 */
	public ECDSAVerifier(final ECKey ecJWK) {

		this(ecJWK.getX().decodeToBigInteger(), ecJWK.getY().decodeToBigInteger(), null);
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * verifier.
	 *
	 * @param x              The 'x' coordinate for the elliptic curve
	 *                       point. Must not be {@code null}.
	 * @param y              The 'y' coordinate for the elliptic curve
	 *                       point. Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 */
	public ECDSAVerifier(final BigInteger x, final BigInteger y, final Set<String> defCritHeaders) {

		if (x == null) {
			throw new IllegalArgumentException("The \"x\" EC coordinate must not be null");
		}

		this.x = x;

		if (y == null) {
			throw new IllegalArgumentException("The \"y\" EC coordinate must not be null");
		}

		this.y = y;

		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}


	/**
	 * Gets the 'x' coordinate for the elliptic curve point.
	 *
	 * @return The 'x' coordinate.
	 */
	public BigInteger getX() {

		return x;
	}


	/**
	 * Gets the 'y' coordinate for the elliptic curve point.
	 *
	 * @return The 'y' coordinate.
	 */
	public BigInteger getY() {

		return y;
	}


	@Override
	public Set<String> getProcessedCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public Set<String> getDeferredCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public boolean verify(final JWSHeader header,
		              final byte[] signedContent, 
		              final Base64URL signature)
		throws JOSEException {

		if (! critPolicy.headerPasses(header)) {
			return false;
		}

		ECDSAParameters initParams = ECDSA.getECDSAParameters(header.getAlgorithm());
		X9ECParameters x9ECParameters = initParams.getX9ECParameters();
		Digest digest = initParams.getDigest();

		byte[] signatureBytes = signature.decode();

		// Split signature into R and S parts
		int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());

		byte[] rBytes = new byte[rsByteArrayLength / 2];
		byte[] sBytes = new byte[rsByteArrayLength / 2];

		try {
			System.arraycopy(signatureBytes, 0, rBytes, 0, rBytes.length);
			System.arraycopy(signatureBytes, rBytes.length, sBytes, 0, sBytes.length);

		} catch (Exception e) {

			throw new JOSEException("Invalid ECDSA signature format: " + e.getMessage(), e);
		}

		BigInteger r = new BigInteger(1, rBytes);
		BigInteger s = new BigInteger(1, sBytes);


		ECCurve curve = x9ECParameters.getCurve();
		ECPoint q = curve.createPoint(x, y);

		ECDomainParameters ecDomainParameters = new ECDomainParameters(
			curve, 
			x9ECParameters.getG(), 
			x9ECParameters.getN(), 
			x9ECParameters.getH(),
			x9ECParameters.getSeed());

		ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(
			q, ecDomainParameters);

		org.bouncycastle.crypto.signers.ECDSASigner verifier = 
			new org.bouncycastle.crypto.signers.ECDSASigner();

		verifier.init(false, ecPublicKeyParameters);

		digest.update(signedContent, 0, signedContent.length);
		byte[] out = new byte[digest.getDigestSize()];
		digest.doFinal(out, 0);

		return verifier.verifySignature(out, r, s);
	}
}
