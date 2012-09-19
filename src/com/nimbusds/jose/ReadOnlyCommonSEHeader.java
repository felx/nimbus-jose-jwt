package com.nimbusds.jose;


import java.net.URL;

import com.nimbusds.util.Base64;
import com.nimbusds.util.Base64URL;


/**
 * Read-only view of {@link CommonSEHeader common JWS/JWE header parameters}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public interface ReadOnlyCommonSEHeader extends ReadOnlyHeader {
	
	
	/**
	 * Gets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
	 *
	 * @return The JSON Web Key (JWK) Set URL parameter, {@code null} if not 
	 *         specified.
	 */
	public URL getJWKURL();
	
	
	/**
	 * Gets the JSON Web Key (JWK) ({@code jwk}) parameter.
	 *
	 * @return The JSON Web Key (JWK) parameter, {@code null} if not
	 *         specified.
	 */
	public JWK getJWK();
	
	
	/**
	 * Gets the X.509 certificate URL ({@code x5u}) parameter.
	 *
	 * @return The X.509 certificate URL parameter, {@code null} if not 
	 *         specified.
	 */
	public URL getX509CertURL();
	
	
	/**
	 * Gets the X.509 certificate thumbprint ({@code x5t}) parameter.
	 *
	 * @return The X.509 certificate thumbprint parameter, {@code null} if 
	 *         not specified.
	 */
	public Base64URL getX509CertThumbprint();
	
	
	/**
	 * Gets the X.509 certificate chain parameter ({@code x5c}) 
	 * corresponding to the key used to sign or encrypt the JWS/JWE object.
	 *
	 * @return The X.509 certificate chain parameter, {@code null} if not
	 *         specified.
	 */
	public Base64[] getX509CertChain();
	
	
	/**
	 * Gets the key ID ({@code kid}) parameter.
	 *
	 * @return The key ID parameter, {@code null} if not specified.
	 */
	public String getKeyID();
}
