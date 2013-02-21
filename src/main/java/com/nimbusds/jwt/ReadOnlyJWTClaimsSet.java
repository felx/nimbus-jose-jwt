package com.nimbusds.jwt;


import java.util.Date;
import java.util.List;
import java.util.Map;

import net.minidev.json.JSONObject;


/**
 * Read-only view of a {@link JWTClaimsSet}.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-02-21)
 */
public interface ReadOnlyJWTClaimsSet {


	/**
	 * Gets the issuer ({@code iss}) claim.
	 *
	 * @return The issuer claim, {@code null} if not specified.
	 */
	public String getIssuer();


	/**
	 * Gets the subject ({@code sub}) claim.
	 *
	 * @return The subject claim, {@code null} if not specified.
	 */
	public String getSubject();


	/**
	 * Gets the audience ({@code aud}) clam.
	 *
	 * @return The audience claim, {@code null} if not specified.
	 */
	public List<String> getAudience();


	/**
	 * Gets the expiration time ({@code exp}) claim.
	 *
	 * @return The expiration time, {@code null} if not specified.
	 */
	public Date getExpirationTime();


	/**
	 * Gets the not-before ({@code nbf}) claim.
	 *
	 * @return The not-before claim, {@code null} if not specified.
	 */
	public Date getNotBeforeTime();


	/**
	 * Gets the issued-at ({@code iat}) claim.
	 *
	 * @return The issued-at claim, {@code null} if not specified.
	 */
	public Date getIssueTime();


	/**
	 * Gets the JWT ID ({@code jti}) claim.
	 *
	 * @return The JWT ID claim, {@code null} if not specified.
	 */
	public String getJWTID();


	/**
	 * Gets the type ({@code typ}) claim.
	 *
	 * @return The type claim, {@code null} if not specified.
	 */
	public String getType();


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
	 * Gets a single claim by name, whether reserved or custom.
	 * 
	 * @param name The name of the claim to get. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 */
	public Object getClaim(final String name);


	/**
	 * Gets all claims, both reserved and custom, as a single map.
	 *
	 * <p>Note that the reserved claims Expiration-Time ({@code exp}),
	 * Not-Before-Time ({@code nbf}) and Issued-At ({@code iat}) will be
	 * returned as {@code java.util.Date} instances.
	 * 
	 * @return All claims, as an unmodifiable map, empty map if none.
	 */
	public Map<String, Object> getAllClaims();


	/**
	 * Returns the JSON object representation of the claims set.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject();
}
