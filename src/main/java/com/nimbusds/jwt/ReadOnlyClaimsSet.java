package com.nimbusds.jwt;


import java.util.Map;

import net.minidev.json.JSONObject;


/**
 * Read-only view of a {@link ClaimsSet}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-08)
 */
public interface ReadOnlyClaimsSet {


	/**
	 * Gets the issuer ({@code iss}) claim.
	 *
	 * @return The issuer claim, {@code null} if not specified.
	 */
	public String getIssuerClaim();


	/**
	 * Gets the subject ({@code sub}) claim.
	 *
	 * @return The subject claim, {@code null} if not specified.
	 */
	public String getSubjectClaim();
	
	
	/**
	 * Gets the audience ({@code aud}) clam.
	 *
	 * @return The audience claim, {@code null} if not specified.
	 */
	public String[] getAudienceClaim();


	/**
	 * Gets the expiration time ({@code exp}) claim.
	 *
	 * @return The expiration time, -1 if not specified.
	 */
	public long getExpirationTimeClaim();
	
	
	/**
	 * Gets the not-before ({@code nbf}) claim.
	 *
	 * @return The not-before claim, -1 if not specified.
	 */
	public long getNotBeforeClaim();
	
	
	/**
	 * Gets the issued-at ({@code iat}) claim.
	 *
	 * @return The issued-at claim, -1 if not specified.
	 */
	public long getIssuedAtClaim();
	
	
	/**
	 * Gets the JWT ID ({@code jti}) claim.
	 *
	 * @return The JWT ID claim, {@code null} if not specified.
	 */
	public String getJWTIDClaim();
	
	
	/**
	 * Gets the type ({@code typ}) claim.
	 *
	 * @return The type claim, {@code null} if not specified.
	 */
	public String getTypeClaim();
	
	
	/**
	 * Gets a custom (non-reserved) claim.
	 * 
	 * @param name The name of the custom claim. Must not be {@code null}.
	 *
	 * @return The value of the custom claim, {@code null} if not specified.
	 */
	public Object getCustomClaim(final String name);
	
	
	/**
	 * Gets the custom (non-reserved) claims.
	 *
	 * @return The custom claims, as a unmodifiable map, empty map if none.
	 */
	public Map<String,Object> getCustomClaims();
	 
	 
	/**
	 * Returns the JSON object representation of the claims set.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject();
}
