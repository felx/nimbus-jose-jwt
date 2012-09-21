package com.nimbusds.jwt;


/**
 * JSON Web Token (JWT) interface.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-21)
 */
public interface JWT {


	/**
	 * Gets the claims set of the JSON Web Token (JWT).
	 *
	 * @return The claims set, {@code null} if not available (for an 
	 *         encrypted JWT that isn't decrypted).
	 */
	public ClaimsSet getClaimsSet();
}
