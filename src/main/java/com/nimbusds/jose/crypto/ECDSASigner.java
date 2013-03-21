package com.nimbusds.jose.crypto;


import java.math.BigInteger;

import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) signer of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
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
 * @version $version$ (2013-03-21)
 */
@ThreadSafe
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

		if (privateKey == null) {

			throw new IllegalArgumentException("The private key must not be null");
		}

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
	 * @param ecPrivateKeyParameters The EC private key parameters. Must 
	 *                               not be {@code null}.
	 * @param bytes                  The byte array to sign. Must not be 
	 *                               {@code null}.
	 *
	 * @return The ECDSA signature parts R and S.
	 */
	private static BigInteger[] doECDSA(final ECPrivateKeyParameters ecPrivateKeyParameters, 
		                            final byte[] bytes) {

		org.bouncycastle.crypto.signers.ECDSASigner signer = 
			new org.bouncycastle.crypto.signers.ECDSASigner();

		signer.init(true, ecPrivateKeyParameters);
		
		return signer.generateSignature(bytes);
	}


	/**
	 * Converts the specified big integers to byte arrays and returns their
	 * array concatenation.
	 *
	 * @param r                 The R parameter. Must not be {@code null}.
	 * @param s                 The S parameter. Must not be {@code null}.
	 * @param rsByteArrayLength The expected concatenated array length.
	 *
	 * @return The resulting concatenated array.
	 */
	private static byte[] formatSignature(final BigInteger r, 
		                              final BigInteger s,
		                              final int rsByteArrayLength) {

		byte[] rBytes = BigIntegerUtils.toBytesUnsigned(r);
		byte[] sBytes = BigIntegerUtils.toBytesUnsigned(s);

		final int outLength = rBytes.length + sBytes.length;

		byte[] rsBytes = new byte[rsByteArrayLength];

		int i = 0;

		// Copy R bytes to first array half, zero pad front
		int offset = (rsByteArrayLength / 2) - rBytes.length;

		i += offset;

		for (byte rB: rBytes) {

			rsBytes[i++] = rB;
		}

		// Copy S bytes to second array half, zero pad front
		i = rsByteArrayLength / 2;

		offset = (rsByteArrayLength / 2) - sBytes.length;

		i += offset;

		for (byte sB: sBytes) {

			rsBytes[i++] = sB;
		}

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

		BigInteger[] signatureParts = doECDSA(ecPrivateKeyParameters, out);

		int rsByteArrayLength = ECDSAProvider.getSignatureByteArrayLength(header.getAlgorithm());

		return Base64URL.encode(formatSignature(signatureParts[0], 
			                                signatureParts[1], 
			                                rsByteArrayLength));
	}
}
