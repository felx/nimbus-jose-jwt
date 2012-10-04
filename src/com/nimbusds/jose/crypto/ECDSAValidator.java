package com.nimbusds.jose.crypto;


import java.math.BigInteger;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x9.X9ECParameters;

import org.bouncycastle.crypto.Digest;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSHeaderFilter;
import com.nimbusds.jose.sdk.JWSValidator;
import com.nimbusds.jose.sdk.ReadOnlyJWSHeader;

import com.nimbusds.jose.sdk.util.Base64URL;



/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) validator of 
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
 * <p>Accepts the following JWS header parameters:
 *
 * <ul>
 *     <li>{@code alg}
 *     <li>{@code typ}
 *     <li>{@code cty}
 * </ul>
 * 
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
public class ECDSAValidator extends ECDSAProvider implements JWSValidator {


	/**
	 * The accepted JWS header parameters.
	 */
	private static final Set<String> ACCEPTED_HEADER_PARAMETERS;
	
	
	/**
	 * Initialises the accepted JWS header parameters.
	 */
	static {
	
		Set<String> params = new HashSet<String>();
		params.add("alg");
		params.add("typ");
		params.add("cty");
		
		ACCEPTED_HEADER_PARAMETERS = params;
	}
	
	
	/**
	 * The JWS header filter.
	 */
	private DefaultJWSHeaderFilter headerFilter;
	
	
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
	 * validator.
	 *
	 * @param x The 'x' coordinate for the elliptic curve point. Must not be
	 *          {@code null}.
	 * @param y The 'y' coordinate for the elliptic curve point. Must not be 
	 *          {@code null}.
	 */
	public ECDSAValidator(final BigInteger x, final BigInteger y) {

		if (x == null)
			throw new IllegalArgumentException("The \"x\" EC coordinate must not be null");
			
		this.x = x;
		
		if (y == null)
			throw new IllegalArgumentException("The \"y\" EC coordinate must not be null");
			
		this.y = y;
		
		headerFilter = new DefaultJWSHeaderFilter(supportedAlgorithms(), ACCEPTED_HEADER_PARAMETERS);
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
	public JWSHeaderFilter getJWSHeaderFilter() {
	
		return headerFilter;
	}


	@Override
	public boolean validate(final ReadOnlyJWSHeader header, 
	                        final byte[] signedContent, 
			        final Base64URL signature)
		throws JOSEException {
		
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

		org.bouncycastle.crypto.signers.ECDSASigner validator = 
			new org.bouncycastle.crypto.signers.ECDSASigner();
		
		validator.init(false, ecPublicKeyParameters);
		
		digest.update(signedContent, 0, signedContent.length);
		byte[] out = new byte[digest.getDigestSize()];
		digest.doFinal(out, 0);

		return validator.verifySignature(out, r, s);
	}
}
