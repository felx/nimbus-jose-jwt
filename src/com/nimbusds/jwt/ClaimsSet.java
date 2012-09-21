package com.nimbusds.jwt;


import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;


/**
 * JSON Web Token (JWT) claims set.
 *
 * <p>Supports all {@link #getReservedNames reserved claims} of the JWT 
 * specification:
 *
 * <ul>
 *     <li>exp - Expiration Time
 *     <li>nbf - Not Before
 *     <li>iat - Issued At
 *     <li>iss - Issuer
 *     <li>aud - Audience
 *     <li>prn - Principal
 *     <li>jti - JWT ID
 *     <li>typ - Type
 * </ul>
 *
 * <p>The set may also carry {@link #setCustomClaims custom claims}; these will 
 * be serialised and parsed along the reserved ones.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-21)
 */
public class ClaimsSet implements ReadOnlyClaimsSet {


	/**
	 * The reserved claim names.
	 */
	private static final Set<String> RESERVED_CLAIM_NAMES;
	
	
	/**
	 * Initialises the reserved claim name set.
	 */
	static {
		Set<String> n = new HashSet<String>();
		
		n.add("exp");
		n.add("nbf");
		n.add("iat");
		n.add("iss");
		n.add("aud");
		n.add("prn");
		n.add("jti");
		n.add("typ");
		
		RESERVED_CLAIM_NAMES = Collections.unmodifiableSet(n);
	}
	
	
	/**
	 * The expiration time claim.
	 */
	private long exp;
	
	
	/**
	 * The not-before claim.
	 */
	private long nbf;
	
	
	/**
	 * The issued-at claim.
	 */
	private long iat;
	
	
	/**
	 * The issuer claim.
	 */
	private String iss;
	
	
	/**
	 * The audience claim.
	 */
	private String aud;
	
	
	/**
	 * The principal claim.
	 */
	private String prn;
	
	
	/**
	 * The JWT ID claim.
	 */
	private String jti;
	
	
	/**
	 * The type claim.
	 */
	private String typ;
	
	
	/**
	 * Custom claims.
	 */
	private Map<String,Object> customClaims = new HashMap<String,Object>();
	
	
	/**
	 * Creates a new empty claims set.
	 */
	public ClaimsSet() {
	
		// Nothing to do
	}
	
	
	/**
	 * Gets the reserved claim names.
	 *
	 * @return The reserved claim names, as an unmodifiable set.
	 */
	public static Set<String> getReservedNames() {
	
		return RESERVED_CLAIM_NAMES;
	}
	
	
	@Override
	public long getExpirationTimeClaim() {
	
		return exp;
	}
	
	
	/**
	 * Sets the expiration time ({@code exp}) claim.
	 *
	 * @param exp The expiration time, -1 if not specified.
	 */
	public void setExpirationTimeClaim(final long exp) {
	
		this.exp = exp;
	}
	
	
	@Override
	public long getNotBeforeClaim() {
	
		return nbf;
	}
	
	
	/**
	 * Sets the not-before ({@code nbf}) claim.
	 *
	 * @param nbf The not-before claim, -1 if not specified.
	 */
	public void setNotBeforeClaim(final long nbf) {
	
		this.nbf = nbf;
	}
	
	
	@Override
	public long getIssuedAtClaim() {
	
		return iat;
	}
	
	
	/**
	 * Sets the issued-at ({@code iat}) claim.
	 *
	 * @param iat The issued-at claim, -1 if not specified.
	 */
	public void setIssuedAtClaim(final long iat) {
	
		this.iat = iat;
	}
	
	
	@Override
	public String getIssuerClaim() {
	
		return iss;
	}
	
	
	/**
	 * Sets the issuer ({@code iss}) claim.
	 *
	 * @param iss The issuer claim, {@code null} if not specified.
	 */
	public void setIssuerClaim(final String iss) {
	
		this.iss = iss;
	}
	
	
	@Override
	public String getAudienceClaim() {
	
		return iss;
	}
	
	
	/**
	 * Sets the audience ({@code aud}) clam.
	 *
	 * @param aud The audience claim, {@code null} if not specified.
	 */
	public void setAudienceClaim(final String aud) {
	
		this.aud = aud;
	}
	
	
	@Override
	public String getPrincipalClaim() {
	
		return prn;
	}
	
	
	/**
	 * Sets the principal ({@code prn}) claim.
	 *
	 * @param prn The principal claim, {@code null} if not specified.
	 */
	public void setPrincipalClaim(final String prn) {
	
		this.prn = prn;
	}
	
	
	@Override
	public String getJWTIDClaim() {
	
		return jti;
	}
	
	
	/**
	 * Sets the JWT ID ({@code jti}) claim.
	 *
	 * @param jti The JWT ID claim, {@code null} if not specified.
	 */
	public void setJWTIDClaim(final String jti) {
	
		this.jti = jti;
	}
	
	
	@Override
	public String getTypeClaim() {
	
		return typ;
	}
	
	
	/**
	 * Sets the type ({@code typ}) claim.
	 *
	 * @param typ The type claim, {@code null} if not specified.
	 */
	public void setTypeClaim(final String typ) {
	
		this.typ = typ;
	}
	
	
	@Override 
	public Map<String,Object> getCustomClaims() {
	
		return Collections.unmodifiableMap(customClaims);
	}
	
	
	/**
	 * Sets the custom (non-reserved) claims. The values must be 
	 * serialisable to a JSON entity, otherwise will be ignored.
	 *
	 * @param customClaims The custom claims, empty map or {@code null} if
	 *                     none.
	 */
	public void setCustomClaims(final Map<String,Object> customClaims) {
	
		if (customClaims == null)
			return;
		
		this.customClaims = customClaims;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
	
		// TBD
		return null;
	}
	
	
	/**
	 * Parses a JSON Web Token (JWT) claims set from the specified
	 * JSON object representation.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The claims set.
	 *
	 * @throws
	 */
	public static ClaimsSet parse(final JSONObject json) {
	
		// TBD
		return null;
	}
}
