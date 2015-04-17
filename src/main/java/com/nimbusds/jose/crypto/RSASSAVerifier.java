package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-17)
 */
@ThreadSafe
public class RSASSAVerifier extends RSASSAProvider implements JWSVerifier {


	/**
	 * The JWS header validator.
	 */
	private final JWSHeaderValidator headerValidator;


	/**
	 * The public RSA key.
	 */
	private final RSAPublicKey publicKey;


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
	 *
	 * @param publicKey The public RSA key. Must not be {@code null}.
	 * @param alg       The expected RSA JWS algorithm. Must be
	 *                  {@link #SUPPORTED_ALGORITHMS supported} and not
	 *                  {@code null}.
	 */
	public RSASSAVerifier(final RSAPublicKey publicKey, JWSAlgorithm alg) {

		this(publicKey, new DefaultJWSHeaderValidator(alg));
		AlgorithmSupport.ensure(SUPPORTED_ALGORITHMS, alg);
	}


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
	 *
	 * @param publicKey       The public RSA key. Must not be {@code null}.
	 * @param headerValidator The JWS header validator. Must not be
	 *                        {@code null}.
	 */
	public RSASSAVerifier(final RSAPublicKey publicKey,
			      final JWSHeaderValidator headerValidator) {

		this(publicKey, headerValidator, null);
	}


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
	 *
	 * @param publicKey       The public RSA key. Must not be {@code null}.
	 * @param headerValidator The JWS header validator. Must not be
	 *                        {@code null}.
	 * @param jcaSpec         The JCA provider specification, {@code null}
	 *                        implies the default one.
	 */
	public RSASSAVerifier(final RSAPublicKey publicKey,
			      final JWSHeaderValidator headerValidator,
			      final JWSJCAProviderSpec jcaSpec) {

		super(jcaSpec);

		if (publicKey == null) {
			throw new IllegalArgumentException("The public RSA key must not be null");
		}

		this.publicKey = publicKey;

		if (headerValidator == null) {
			throw new IllegalArgumentException("The JWS header validator must not be null");
		}

		this.headerValidator = headerValidator;
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
	public JWSHeaderValidator getHeaderValidator() {

		return headerValidator;
	}


	@Override
	public boolean verify(final JWSHeader header,
		              final byte[] signedContent, 
		              final Base64URL signature)
		throws JOSEException {

		headerValidator.validate(header);

		Provider provider = getJCAProviderSpec() != null ? getJCAProviderSpec().getProvider() : null;

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
