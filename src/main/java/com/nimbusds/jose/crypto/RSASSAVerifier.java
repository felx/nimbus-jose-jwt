package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.util.Base64URL;


/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) verifier of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS512}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS512}
 * </ul>
 *
 * <p>Accepts all {@link com.nimbusds.jose.JWSHeader#getRegisteredParameterNames
 * registered JWS header parameters}. Use {@link #setAcceptedAlgorithms} to
 * restrict the acceptable JWS algorithms.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-20)
 */
@ThreadSafe
public class RSASSAVerifier extends RSASSAProvider implements JWSVerifier {


	/**
	 * The accepted JWS algorithms.
	 */
	private Set<JWSAlgorithm> acceptedAlgs =
		new HashSet<JWSAlgorithm>(supportedAlgorithms());


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey publicKey;


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 */
	public RSASSAVerifier(final RSAPublicKey publicKey) {

		if (publicKey == null) {

			throw new IllegalArgumentException("The public RSA key must not be null");
		}

		this.publicKey = publicKey;
	}


	/**
	 * Gets the public RSA key.
	 *
	 * @return The public RSA key.
	 */
	public RSAPublicKey getPublicKey() {

		return publicKey;
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
	public boolean verify(final ReadOnlyJWSHeader header, 
		              final byte[] signedContent, 
		              final Base64URL signature)
		throws JOSEException {

		Signature verifier = getRSASignerAndVerifier(header.getAlgorithm(), provider);

		try {
			verifier.initVerify(publicKey);

		} catch (InvalidKeyException e) {

			throw new JOSEException("Invalid public RSA key: " + e.getMessage(), e);
		}

		try {
			verifier.update(signedContent);
			return verifier.verify(signature.decode());

		} catch (SignatureException e) {

			return false;
		}
	}
}
