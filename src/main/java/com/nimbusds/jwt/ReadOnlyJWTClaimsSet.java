package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import net.minidev.json.JSONObject;


/**
 * Read-only view of a {@link JWTClaimsSet}.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2015-01-12)
 */
public interface ReadOnlyJWTClaimsSet {


	/**
	 * Gets the issuer ({@code iss}) claim.
	 *
	 * @return The issuer claim, {@code null} if not specified.
	 */
	String getIssuer();


	/**
	 * Gets the subject ({@code sub}) claim.
	 *
	 * @return The subject claim, {@code null} if not specified.
	 */
	String getSubject();


	/**
	 * Gets the audience ({@code aud}) clam.
	 *
	 * @return The audience claim, {@code null} if not specified.
	 */
	List<String> getAudience();


	/**
	 * Gets the expiration time ({@code exp}) claim.
	 *
	 * @return The expiration time, {@code null} if not specified.
	 */
	Date getExpirationTime();


	/**
	 * Gets the not-before ({@code nbf}) claim.
	 *
	 * @return The not-before claim, {@code null} if not specified.
	 */
	Date getNotBeforeTime();


	/**
	 * Gets the issued-at ({@code iat}) claim.
	 *
	 * @return The issued-at claim, {@code null} if not specified.
	 */
	Date getIssueTime();


	/**
	 * Gets the JWT ID ({@code jti}) claim.
	 *
	 * @return The JWT ID claim, {@code null} if not specified.
	 */
	String getJWTID();


	/**
	 * Gets a custom (non-registered) claim.
	 * 
	 * @param name The name of the custom claim. Must not be {@code null}.
	 *
	 * @return The value of the custom claim, {@code null} if not 
	 *         specified.
	 */
	Object getCustomClaim(final String name);


	/**
	 * Gets the custom (non-registered) claims.
	 *
	 * @return The custom claims, as a unmodifiable map, empty map if none.
	 */
	Map<String,Object> getCustomClaims();
	

	/**
	 * Gets the specified claim (registered or custom).
	 * 
	 * @param name The name of the claim. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 */
	Object getClaim(final String name);
	
	
	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.String}.
	 * 
	 * @param name The name of the claim. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 * 
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	String getStringClaim(final String name)
		throws ParseException;


	/**
	 * Gets the specified claims (registered or custom) as a
	 * {@link java.lang.String} array.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	String[] getStringArrayClaim(final String name)
		throws ParseException;


	/**
	 * Gets the specified claims (registered or custom) as a
	 * {@link java.lang.String} list.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	List<String> getStringListClaim(final String name)
		throws ParseException;

	
	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Boolean}.
	 * 
	 * @param name The name of the claim. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 * 
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	Boolean getBooleanClaim(final String name)
		throws ParseException;
	
	
	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Integer}.
	 * 
	 * @param name The name of the claim. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 * 
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	Integer getIntegerClaim(final String name)
		throws ParseException;
	
	
	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Long}.
	 * 
	 * @param name The name of the claim. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 * 
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	Long getLongClaim(final String name)
		throws ParseException;
	
	
	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Float}.
	 * 
	 * @param name The name of the claim. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 * 
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	Float getFloatClaim(final String name)
		throws ParseException;
	
	
	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Double}.
	 * 
	 * @param name The name of the claim. Must not be {@code null}.
	 * 
	 * @return The value of the claim, {@code null} if not specified.
	 * 
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	Double getDoubleClaim(final String name)
		throws ParseException;


	/**
	 * Gets all claims, both registered and custom, as a single map.
	 *
	 * <p>Note that the registered claims Expiration-Time ({@code exp}),
	 * Not-Before-Time ({@code nbf}) and Issued-At ({@code iat}) will be
	 * returned as {@code java.util.Date} instances.
	 * 
	 * @return All claims, as an unmodifiable map, empty map if none.
	 */
	Map<String,Object> getAllClaims();


	/**
	 * Returns the JSON object representation of the claims set. The claims
	 * are serialised according to their insertion order.
	 *
	 * @return The JSON object representation.
	 */
	JSONObject toJSONObject();
}
