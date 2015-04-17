package com.nimbusds.jose.crypto;


import java.nio.charset.Charset;
import java.security.Provider;

import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
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
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-17)
 */
@ThreadSafe
public class MACVerifier extends MACProvider implements JWSVerifier {


	/**
	 * The JWS header validator.
	 */
	private final JWSHeaderValidator headerValidator;


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param secret The secret. Must be at least 256 bits long and not
	 *               {@code null}.
	 * @param alg    The expected HMAC JWS algorithm. Must be
	 *               {@link #SUPPORTED_ALGORITHMS supported} and not
	 *               {@code null}.
	 */
	public MACVerifier(final byte[] secret, final JWSAlgorithm alg) {

		this(secret, new DefaultJWSHeaderValidator(alg));
		AlgorithmSupport.ensure(SUPPORTED_ALGORITHMS, alg);
	}


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param secretString The secret as a UTF-8 encoded string. Must be at
	 *                     least 256 bits long and not {@code null}.
	 * @param alg          The expected HMAC JWS algorithm. Must be
	 *                     {@link #SUPPORTED_ALGORITHMS supported} and not
	 *                     {@code null}.
	 */
	public MACVerifier(final String secretString, final JWSAlgorithm alg) {

		this(secretString.getBytes(Charset.forName("UTF-8")), new DefaultJWSHeaderValidator(alg));
		AlgorithmSupport.ensure(SUPPORTED_ALGORITHMS, alg);
	}


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param secretKey The secret key. Must be at least 256 bits long and
	 *                  not {@code null}.
	 * @param alg       The expected HMAC JWS algorithm. Must be
	 *                  {@link #SUPPORTED_ALGORITHMS supported} and not
	 *                  {@code null}.
	 */
	public MACVerifier(final SecretKey secretKey, final JWSAlgorithm alg) {

		this(secretKey.getEncoded(), new DefaultJWSHeaderValidator(alg));
		AlgorithmSupport.ensure(SUPPORTED_ALGORITHMS, alg);
	}


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param jwk The secret as a JWK. Must be at least 256 bits long and
	 *            not {@code null}.
	 * @param alg The expected HMAC JWS algorithm. Must be
	 *            {@link #SUPPORTED_ALGORITHMS supported} and not
	 *            {@code null}.
	 */
	public MACVerifier(final OctetSequenceKey jwk, final JWSAlgorithm alg) {

		this(jwk.toByteArray(), alg);
		AlgorithmSupport.ensure(SUPPORTED_ALGORITHMS, alg);
	}


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param secret          The secret. Must be at least 256 bits long
	 *                        and not {@code null}.
	 * @param headerValidator The JWS header validator. Must not be
	 *                        {@code null}.
	 */
	public MACVerifier(final byte[] secret,
			   final JWSHeaderValidator headerValidator) {

		this(secret, headerValidator, null);
	}


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param secret          The secret. Must be at least 256 bits long
	 *                        and not {@code null}.
	 * @param headerValidator The JWS header validator. Must not be
	 *                        {@code null}.
	 * @param jcaSpec         The JCA provider specification, {@code null}
	 *                        implies the default one.
	 */
	public MACVerifier(final byte[] secret,
			   final JWSHeaderValidator headerValidator,
			   final JWSJCAProviderSpec jcaSpec) {

		super(secret, jcaSpec);

		if (headerValidator == null) {
			throw new IllegalArgumentException("The JWS header validator must not be null");
		}

		this.headerValidator = headerValidator;
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

		String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());

		headerValidator.validate(header);

		Provider provider = getJCAProviderSpec() != null ? getJCAProviderSpec().getProvider() : null;
		byte[] expectedHMAC = HMAC.compute(jcaAlg, getSecret(), signedContent, provider);
		return ConstantTimeUtils.areEqual(expectedHMAC, signature.decode());
	}
}
