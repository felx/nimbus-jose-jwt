package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;

import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) signer of 
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
 * @version $version$ (2015-05-31)
 */
@ThreadSafe
public class ECDSASigner extends ECDSAProvider implements JWSSigner {


	/**
	 * The private EC key.
	 */
	private final ECPrivateKey privateKey;


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * signer.
	 *
	 * @param privateKey The private EC key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSASigner(final ECPrivateKey privateKey)
		throws JOSEException {

		super(ECDSA.resolveAlgorithm(privateKey));

		this.privateKey = privateKey;
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must contain a private part.
	 *              Must not be {@code null}.
	 *
	 * @throws JOSEException If the EC JWK doesn't contain a private part,
	 *                       its extraction failed, or the elliptic curve
	 *                       is not supported.
	 */
	public ECDSASigner(final ECKey ecJWK)
		throws JOSEException {

		super(ECDSA.resolveAlgorithm(ecJWK.getCurve()));

		if (! ecJWK.isPrivate()) {
			throw new JOSEException("The EC JWK doesn't contain a private part");
		}

		privateKey = ecJWK.toECPrivateKey();
	}


	/**
	 * Returns the private EC key.
	 *
	 * @return The private EC key.
	 */
	public ECPrivateKey getPrivateKey() {

		return privateKey;
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
	public Base64URL sign(final JWSHeader header, final byte[] signingInput)
		throws JOSEException {

		final JWSAlgorithm alg = header.getAlgorithm();

		if (! supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}

		// DER-encoded signature, according to JCA spec
		byte[] jcaSignature;

		try {
			Signature dsa = ECDSA.getSignerAndVerifier(alg, getJCAProvider());
			dsa.initSign(privateKey);
			dsa.update(signingInput);
			jcaSignature = dsa.sign();

		} catch (InvalidKeyException | SignatureException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		ASN1Sequence sequence = ASN1Sequence.getInstance(jcaSignature);
		ASN1Integer r = (ASN1Integer)sequence.getObjectAt(0);
		ASN1Integer s = (ASN1Integer)sequence.getObjectAt(1);

		int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());

		return Base64URL.encode(formatSignature(r.getValue(),
			                                s.getValue(),
			                                rsByteArrayLength));
	}
}
