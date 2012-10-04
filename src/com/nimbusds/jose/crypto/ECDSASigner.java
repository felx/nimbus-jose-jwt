package com.nimbusds.jose.crypto;


import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9ECParameters;

import org.bouncycastle.crypto.Digest;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSSigner;
import com.nimbusds.jose.sdk.ReadOnlyJWSHeader;

import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) signer of 
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
 * @version $version$ (2012-10-04)
 */
public class ECDSASigner extends ECDSAProvider implements JWSSigner {


	/**
	 * The private key.
	 */
	private final BigInteger privateKey;
	
	
	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * signer.
	 *
	 * @param privateKey The private key ('d' parameter). Must not be 
	 *                   {@code null}.
	 */
	public ECDSASigner(final BigInteger privateKey) {

		if (privateKey == null)
			throw new IllegalArgumentException("The private key must not be null");
		
		this.privateKey = privateKey;
	}
	
	
	/**
	 * Gets the private key ('d' parameter).
	 *
	 * @return The private key.
	 */
	public BigInteger getPrivateKey() {
	
		return privateKey;
	}
	
	
	/**
	 * Performs the actual ECDSA signing.
	 *
	 * @param ecPrivateKeyParameters The EC private key parameters. Must not
	 *                               be {@code null}.
	 * @param bytes                  The byte array to sign. Must not be 
	 *                               {@code null}.
	 *
	 * @return The ECDSA signture.
	 */
	private static byte[] doECDSA(final ECPrivateKeyParameters ecPrivateKeyParameters, 
	                              final byte[] bytes) {

		org.bouncycastle.crypto.signers.ECDSASigner signer = 
			new org.bouncycastle.crypto.signers.ECDSASigner();
		
		signer.init(true, ecPrivateKeyParameters);
		BigInteger[] res = signer.generateSignature(bytes);
		BigInteger r = res[0];
		BigInteger s = res[1];

		return formatSignature(r, s);
	}
	
	
	/**
	 * Converts the specified big integers to byte arrays and returns their
	 * 64-byte array concatenation.
	 *
	 * @param r The R parameter. Must not be {@code null}.
	 * @param s The S parameter. Must not be {@code null}.
	 *
	 * @return The resulting 64-byte array.
	 */
	private static byte[] formatSignature(final BigInteger r, final BigInteger s) {
		
		byte[] rBytes = r.toByteArray();
		byte[] sBytes = s.toByteArray();
		
		byte[] rsBytes = new byte[64];
		
		for (int i=0; i<rsBytes.length; i++)
			rsBytes[i] = 0;
		
		if (rBytes.length >= 32)
			System.arraycopy(rBytes, rBytes.length - 32, rsBytes, 0, 32);
		
		else
			System.arraycopy(rBytes, 0, rsBytes, 32 - rBytes.length, rBytes.length);
		
		
		if (sBytes.length >= 32)
			System.arraycopy(sBytes, sBytes.length - 32, rsBytes, 32, 32);
		
		else
			System.arraycopy(sBytes, 0, rsBytes, 64 - sBytes.length, sBytes.length);
		
		
		return rsBytes;
	}


	@Override
	public Base64URL sign(final ReadOnlyJWSHeader header, final byte[] signableContent)
		throws JOSEException {
		
		ECDSAParameters initParams = getECDSAParameters(header.getAlgorithm());
		X9ECParameters x9ECParameters = initParams.getX9ECParameters();
		Digest digest = initParams.getDigest();
		
		ECDomainParameters ecParameterSpec = new ECDomainParameters(
							x9ECParameters.getCurve(), 
							x9ECParameters.getG(), 
							x9ECParameters.getN(), 
							x9ECParameters.getH(), 
							x9ECParameters.getSeed());
		
		ECPrivateKeyParameters ecPrivateKeyParameters = 
			new ECPrivateKeyParameters(privateKey, ecParameterSpec);

		digest.update(signableContent, 0, signableContent.length);
		byte[] out = new byte[digest.getDigestSize()];
		digest.doFinal(out, 0);

		byte[] sig = doECDSA(ecPrivateKeyParameters, out);

		return Base64URL.encode(sig);
	}
}
