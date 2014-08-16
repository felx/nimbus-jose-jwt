package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;


/**
 * Message Authentication Code (MAC) verifier of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS512}
 * </ul>
 *
 * <p>Accepts all {@link com.nimbusds.jose.JWSHeader#getRegisteredParameterNames
 * registered JWS header parameters}. Use {@link #setAcceptedAlgorithms} to
 * restrict the acceptable JWS algorithms.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
@ThreadSafe
public class MACVerifier extends MACProvider implements JWSVerifier {


	/**
	 * The accepted JWS algorithms.
	 */
	private Set<JWSAlgorithm> acceptedAlgs =
		new HashSet<JWSAlgorithm>(supportedAlgorithms());


	/**
	 * The critical header parameter checker.
	 */
	private final CriticalHeaderParameterChecker critParamChecker =
		new CriticalHeaderParameterChecker();


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param sharedSecret The shared secret. Must not be {@code null}.
	 */
	public MACVerifier(final byte[] sharedSecret) {

		super(sharedSecret);
	}


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param sharedSecretString The shared secret as a UTF-8 encoded
	 *                           string. Must not be {@code null}.
	 */
	public MACVerifier(final String sharedSecretString) {

		super(sharedSecretString);
	}


	@Override
	public Set<JWSAlgorithm> getAcceptedAlgorithms() {

		return acceptedAlgs;
	}


	@Override
	public void setAcceptedAlgorithms(final Set<JWSAlgorithm> acceptedAlgs) {

		if (acceptedAlgs == null) {
			throw new IllegalArgumentException("The accepted JWS algorithms must not be null");
		}

		if (! supportedAlgorithms().containsAll(acceptedAlgs)) {
			throw new IllegalArgumentException("Unsupported JWS algorithm(s)");
		}

		this.acceptedAlgs = acceptedAlgs;
	}


	@Override
	public Set<String> getIgnoredCriticalHeaderParameters() {

		return critParamChecker.getIgnoredCriticalHeaders();
	}


	@Override
	public void setIgnoredCriticalHeaderParameters(final Set<String> headers) {

		critParamChecker.setIgnoredCriticalHeaders(headers);
	}


	@Override
	public boolean verify(final JWSHeader header,
		              final byte[] signedContent, 
		              final Base64URL signature)
		throws JOSEException {

		String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());

		if (! critParamChecker.headerPasses(header)) {
			return false;
		}

		byte[] hmac = HMAC.compute(jcaAlg, getSharedSecret(), signedContent, provider);
		Base64URL expectedSignature = Base64URL.encode(hmac);
		return expectedSignature.equals(signature);
	}
}
