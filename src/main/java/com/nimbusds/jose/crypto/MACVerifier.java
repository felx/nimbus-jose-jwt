package com.nimbusds.jose.crypto;


import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.DefaultJWSHeaderFilter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeaderFilter;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.ReadOnlyJWSHeader;
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
 * registered JWS header parameters}. Modify the {@link #getJWSHeaderFilter
 * header filter} properties to restrict the acceptable JWS algorithms and
 * header parameters, or to allow custom JWS header parameters.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-10-07)
 */
@ThreadSafe
public class MACVerifier extends MACProvider implements JWSVerifier {


	/**
	 * The JWS header filter.
	 */
	private final DefaultJWSHeaderFilter headerFilter;


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param sharedSecret The shared secret. Must not be {@code null}.
	 */
	public MACVerifier(final byte[] sharedSecret) {

		super(sharedSecret);

		headerFilter = new DefaultJWSHeaderFilter(supportedAlgorithms());
	}


	/**
	 * Creates a new Message Authentication (MAC) verifier.
	 *
	 * @param sharedSecretString The shared secret as a UTF-8 encoded
	 *                           string. Must not be {@code null}.
	 */
	public MACVerifier(final String sharedSecretString) {

		super(sharedSecretString);

		headerFilter = new DefaultJWSHeaderFilter(supportedAlgorithms());
	}


	@Override
	public JWSHeaderFilter getJWSHeaderFilter() {

		return headerFilter;
	}


	@Override
	public boolean verify(final ReadOnlyJWSHeader header, 
		              final byte[] signedContent, 
		              final Base64URL signature)
		throws JOSEException {

		String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());

		byte[] hmac = HMAC.compute(jcaAlg, getSharedSecret(), signedContent);

		Base64URL expectedSignature = Base64URL.encode(hmac);

		if (expectedSignature.equals(signature)) {

			return true;

		} else {

			return false;
		}
	}
}
