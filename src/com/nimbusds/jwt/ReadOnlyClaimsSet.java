package com.nimbusds.jwt;


import java.util.Map;

import net.minidev.json.JSONObject;


/**
 * Read-only view of a {@link ClaimsSet}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-21)
 */
public interface ReadOnlyClaimsSet {


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
	 * Gets the issuer ({@code iss}) claim.
	 *
	 * @return The issuer claim, {@code null} if not specified.
	 */
	public String getIssuerClaim();
	
	
	/**
	 * Gets the audience ({@code aud}) clam.
	 *
	 * @return The audience claim, {@code null} if not specified.
	 */
	public String getAudienceClaim();
	
	
	/**
	 * Gets the principal ({@code prn}) claim.
	 *
	 * @return The principal claim, {@code null} if not specified.
	 */
	public String getPrincipalClaim();
	
	
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
