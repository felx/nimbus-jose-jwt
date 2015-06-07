package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

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
 * @version $version$ (2015-06-07)
 */
@ThreadSafe
public class ECDSAVerifier extends ECDSAProvider implements JWSVerifier, CriticalHeaderParamsAware {


	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * The public EC key.
	 */
	private final ECPublicKey publicKey;


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA) 
	 * verifier.
	 *
	 * @param publicKey The public EC key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSAVerifier(final ECPublicKey publicKey)
		throws JOSEException {

		this(publicKey, null);
	}



	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * verifier.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSAVerifier(final ECKey ecJWK)
		throws JOSEException {

		this(ecJWK.toECPublicKey());
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * verifier.
	 *
	 * @param publicKey      The public EC key. Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSAVerifier(final ECPublicKey publicKey, final Set<String> defCritHeaders)
		throws JOSEException {

		super(ECDSA.resolveAlgorithm(publicKey));

		this.publicKey = publicKey;

		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}


	/**
	 * Returns the public EC key.
	 *
	 * @return The public EC key.
	 */
	public ECPublicKey getPublicKey() {

		return publicKey;
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

		final JWSAlgorithm alg = header.getAlgorithm();

		if (! supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}

		if (! critPolicy.headerPasses(header)) {
			return false;
		}

		final byte[] jwsSignature = signature.decode();

		final byte[] derSignature;

		try {
			derSignature = ECDSA.transcodeSignatureToDER(jwsSignature);
		} catch (JOSEException e) {
			// Invalid signature format
			return false;
		}

		Signature sig = ECDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());

		try {
			sig.initVerify(publicKey);
			sig.update(signedContent);
			return sig.verify(derSignature);

		} catch (InvalidKeyException e) {
			throw new JOSEException("Invalid EC public key: " + e.getMessage(), e);
		} catch (SignatureException e) {
			return false;
		}
	}
}
