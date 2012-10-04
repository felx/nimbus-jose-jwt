package com.nimbusds.jose.crypto;


import java.util.HashSet;
import java.util.Set;

import java.security.InvalidKeyException;

import javax.crypto.Mac;

import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.sdk.JOSEException;
import com.nimbusds.jose.sdk.JWSHeaderFilter;
import com.nimbusds.jose.sdk.JWSValidator;
import com.nimbusds.jose.sdk.ReadOnlyJWSHeader;

import com.nimbusds.jose.sdk.util.Base64URL;



/**
 * Message Authentication Code (MAC) validator of 
 * {@link com.nimbusds.jose.sdk.JWSObject JWS objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.sdk.JWSAlgorithm#HS512}
 * </ul>
 *
 * <p>Accepts the following JWS header parameters:
 *
 * <ul>
 *     <li>{@code alg}
 *     <li>{@code typ}
 *     <li>{@code cty}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
public class MACValidator extends MACProvider implements JWSValidator {


	/**
	 * The accepted JWS header parameters.
	 */
	private static final Set<String> ACCEPTED_HEADER_PARAMETERS;
	
	
	/**
	 * Initialises the accepted JWS header parameters.
	 */
	static {
	
		Set<String> params = new HashSet<String>();
		params.add("alg");
		params.add("typ");
		params.add("cty");
		
		ACCEPTED_HEADER_PARAMETERS = params;
	}
	
	
	/**
	 * The JWS header filter.
	 */
	private DefaultJWSHeaderFilter headerFilter;
	
	 
        /**
         * Creates a new Message Authentication (MAC) validator.
         *
         * @param sharedSecret The shared secret. Must not be {@code null}.
         */
        public MACValidator(final byte[] sharedSecret) {

                super(sharedSecret);
		
		headerFilter = new DefaultJWSHeaderFilter(supportedAlgorithms(), ACCEPTED_HEADER_PARAMETERS);
        }
	
	
	@Override
	public JWSHeaderFilter getJWSHeaderFilter() {
	
		return headerFilter;
	}


        @Override
        public boolean validate(final ReadOnlyJWSHeader header, 
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
                
                if (expectedSignature.equals(signature))
                        return true;
                else
                        return false;
        }
}
