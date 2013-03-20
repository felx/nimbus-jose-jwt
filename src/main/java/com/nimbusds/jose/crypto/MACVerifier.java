package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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
 * <p>Accepts all {@link com.nimbusds.jose.JWSHeader#getReservedParameterNames
 * reserved JWS header parameters}. Modify the {@link #getJWSHeaderFilter
 * header filter} properties to restrict the acceptable JWS algorithms and
 * header parameters, or to allow custom JWS header parameters.
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-20)
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


	@Override
	public JWSHeaderFilter getJWSHeaderFilter() {

		return headerFilter;
	}


	@Override
	public boolean verify(final ReadOnlyJWSHeader header, 
		              final byte[] signedContent, 
		              final Base64URL signature)
		throws JOSEException {

		Mac mac = getMAC(header.getAlgorithm());

		try {
			mac.init(new SecretKeySpec(getSharedSecret(), mac.getAlgorithm()));

		} catch (InvalidKeyException e) {

			throw new JOSEException("Invalid HMAC key: " + e.getMessage(), e);
		}

		mac.update(signedContent);

		Base64URL expectedSignature = Base64URL.encode(mac.doFinal());

		if (expectedSignature.equals(signature)) {

			return true;

		} else {

			return false;
		}
	}
}
