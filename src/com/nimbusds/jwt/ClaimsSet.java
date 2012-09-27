package com.nimbusds.jwt;


import java.text.ParseException;

import java.util.Collections;
import java.util.Iterator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.sdk.util.JSONObjectUtils;


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
 * @version $version$ (2012-09-27)
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
	private long exp = -1l;
	
	
	/**
	 * The not-before claim.
	 */
	private long nbf = -1l;
	
	
	/**
	 * The issued-at claim.
	 */
	private long iat = -1l;
	
	
	/**
	 * The issuer claim.
	 */
	private String iss = null;
	
	
	/**
	 * The audience claim.
	 */
	private String aud = null;
	
	
	/**
	 * The principal claim.
	 */
	private String prn = null;
	
	
	/**
	 * The JWT ID claim.
	 */
	private String jti = null;
	
	
	/**
	 * The type claim.
	 */
	private String typ = null;
	
	
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
	
		return aud;
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
	public Object getCustomClaim(final String name) {
	
		return customClaims.get(name);
	}
	
	
	/**
	 * Sets a custom (public or private) claim.
	 *
	 * @param name  The name of the custom claim. Must not be {@code null}.
	 * @param value The value of the custom claim, should map to a valid 
	 *              JSON entity, {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the specified custom claim name
	 *                                  matches a reserved claim name.
	 */
	public void setCustomClaim(final String name, final Object value) {
	
		if (getReservedNames().contains(name))
			throw new IllegalArgumentException("The claim name \"" + name + "\" matches a reserved name");
		
		customClaims.put(name, value);
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
	
		JSONObject o = new JSONObject(customClaims);
		
		if (exp > -1)
			o.put("exp", exp);
		
		if (nbf > -1)
			o.put("nbf", nbf);
			
		if (iat > -1)
			o.put("iat", iat);
		
		if (iss != null)
			o.put("iss", iss);
		
		if (aud != null)
			o.put("aud", aud);
		
		if (prn != null)
			o.put("prn", prn);
		
		if (jti != null)
			o.put("jti", jti);
		
		if (typ != null)
			o.put("typ", typ);
		
		return o;
	}
	
	
	/**
	 * Parses a JSON Web Token (JWT) claims set from the specified
	 * JSON object representation.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The claims set.
	 *
	 * @throws ParseException If the specified JSON object doesn't represent
	 *                        a valid JWT claims set.
	 */
	public static ClaimsSet parse(final JSONObject json)
		throws ParseException {
	
		ClaimsSet cs = new ClaimsSet();
	
		// Parse reserved + custom params
		
		Iterator<String> it = json.keySet().iterator();
		
		while (it.hasNext()) {
			
			String name = it.next();
			
			if (name.equals("exp"))
				cs.setExpirationTimeClaim(JSONObjectUtils.getLong(json, "exp"));
			
			else if (name.equals("nbf"))
				cs.setNotBeforeClaim(JSONObjectUtils.getLong(json, "nbf"));
			
			else if (name.equals("iat"))
				cs.setIssuedAtClaim(JSONObjectUtils.getLong(json, "iat"));
				
			else if (name.equals("iss"))
				cs.setIssuerClaim(JSONObjectUtils.getString(json, "iss"));
				
			else if (name.equals("aud"))
				cs.setAudienceClaim(JSONObjectUtils.getString(json, "aud"));
				
			else if (name.equals("prn"))
				cs.setPrincipalClaim(JSONObjectUtils.getString(json, "prn"));
			
			else if (name.equals("jti"))
				cs.setJWTIDClaim(JSONObjectUtils.getString(json, "jti"));
			
			else if (name.equals("typ"))
				cs.setTypeClaim(JSONObjectUtils.getString(json, "typ"));
			
			else
				cs.setCustomClaim(name, json.get(name));
		}
		
		
		return cs;
	}
}
