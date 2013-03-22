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
 * @version $version$ (2013-03-22)
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


	@Override
	public Base64URL sign(final ReadOnlyJWSHeader header, final byte[] signableContent)
		throws JOSEException {

		String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());

		byte[] hmac = HMAC.compute(jcaAlg, getSharedSecret(), signableContent);

		return Base64URL.encode(hmac);
	}
}
