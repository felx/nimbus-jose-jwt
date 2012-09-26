package com.nimbusds.jose.crypto;


import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9ECParameters;

import org.bouncycastle.crypto.Digest;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSVerifier;
import com.nimbusds.jose.sdk.ReadOnlyJWSHeader;

import com.nimbusds.jose.sdk.util.Base64URL;



/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) verifier of 
 * {@link com.nimbusds.jose.sdk.JWSObject JWS objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#ES256}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#ES384}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#ES512}
 * </ul>
 * 
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
 */
public class ECDSAVerifier extends ECDSAProvider implements JWSVerifier {


	/**
	 * The x elliptic curve parameter.
	 */
	private final BigInteger x;
	
	
	/**
	 * The y elliptic curve parameter.
	 */
	private final BigInteger y;
	
	
	
	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
	 *
	 * @param x The x elliptic curve parameter. Must not be {@code null}.
	 * @param y The y elliptic curve parameter. Must not be {@code null}.
	 */
	public ECDSAVerifier(final BigInteger x, final BigInteger y) {

		if (x == null)
			throw new IllegalArgumentException("The \"x\" EC parameter must not be null");
			
		this.x = x;
		
		if (y == null)
			throw new IllegalArgumentException("The \"y\" EC parameter must not be null");
			
		this.y = y;
	}


	@Override
	public boolean verify(final ReadOnlyJWSHeader header, 
	                      final byte[] signedContent, 
			      final Base64URL signature)
		throws JOSEException {
		
		ensureAcceptedAlgorithm(header.getAlgorithm());
		
		ECDSAParameters initParams = getECDSAParameters(header.getAlgorithm());
		X9ECParameters x9ECParameters = initParams.getX9ECParameters();
		Digest digest = initParams.getDigest();
		

		byte[] signatureBytes = signature.decode();
		
		byte[] rBytes = new byte[32];
		byte[] sBytes = new byte[32];
		
		try {
			System.arraycopy(signatureBytes, 0, rBytes, 0, 32);
			System.arraycopy(signatureBytes, 32, sBytes, 0, 32);
			
		} catch (Exception e) {
		
			throw new JOSEException("Invalid ECDSA signature format: " + e.getMessage(), e);
		}

		BigInteger r = new BigInteger(1, rBytes);
		BigInteger s = new BigInteger(1, sBytes);
		
		
		ECCurve curve = x9ECParameters.getCurve();
		ECPoint qB = curve.createPoint(x, y, false);
		ECPoint q = new ECPoint.Fp(curve, qB.getX(), qB.getY());
		
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
