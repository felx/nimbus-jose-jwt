package com.nimbusds.jose.crypto;


import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.util.Base64URL;



/**
 * Message Authentication Code (MAC) signer of 
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
 * @version $version$ (2014-01-28)
 */
@ThreadSafe
public class MACSigner extends MACProvider implements JWSSigner {


	/**
	 * Creates a new Message Authentication (MAC) signer.
	 *
	 * @param sharedSecret The shared secret. Must not be {@code null}.
	 */
	public MACSigner(final byte[] sharedSecret) {

		super(sharedSecret);
	}


	/**
	 * Creates a new Message Authentication (MAC) signer.
	 *
	 * @param sharedSecretString The shared secret as a UTF-8 encoded
	 *                           string. Must not be {@code null}.
	 */
	public MACSigner(final String sharedSecretString) {

		super(sharedSecretString);
	}


	@Override
	public Base64URL sign(final ReadOnlyJWSHeader header, final byte[] signingInput)
		throws JOSEException {

		String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
		byte[] hmac = HMAC.compute(jcaAlg, getSharedSecret(), signingInput, provider);
		return Base64URL.encode(hmac);
	}
}
