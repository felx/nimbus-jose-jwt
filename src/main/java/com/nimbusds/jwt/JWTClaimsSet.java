package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * JSON Web Token (JWT) claims set.
 *
 * <p>Supports all {@link #getReservedNames reserved claims} of the JWT 
 * specification:
 *
 * <ul>
 *     <li>iss - Issuer
 *     <li>sub - Subject
 *     <li>aud - Audience
 *     <li>exp - Expiration Time
 *     <li>nbf - Not Before
 *     <li>iat - Issued At
 *     <li>jti - JWT ID
 *     <li>typ - Type
 * </ul>
 *
 * <p>The set may also carry {@link #setCustomClaims custom claims}; these will 
 * be serialised and parsed along the reserved ones.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-23)
 */
public class JWTClaimsSet implements ReadOnlyJWTClaimsSet {


	/**
	 * The reserved claim names.
	 */
	private static final Set<String> RESERVED_CLAIM_NAMES;
	
	
	/**
	 * Initialises the reserved claim name set.
	 */
	static {
		Set<String> n = new HashSet<String>();
		
		n.add("iss");
		n.add("sub");
		n.add("aud");
		n.add("exp");
		n.add("nbf");
		n.add("iat");
		n.add("jti");
		n.add("typ");
		
		RESERVED_CLAIM_NAMES = Collections.unmodifiableSet(n);
	}


	/**
	 * The issuer claim.
	 */
	private String iss = null;


	/**
	 * The subject claim.
	 */
	private String sub = null;


	/**
	 * The audience claim.
	 */
	private List<String> aud = null;
	
	
	/**
	 * The expiration time claim.
	 */
	private Date exp = null;
	
	
	/**
	 * The not-before claim.
	 */
	private Date nbf = null;
	
	
	/**
	 * The issued-at claim.
	 */
	private Date iat = null;
	
	
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
	 * Creates a new empty JWT claims set.
	 */
	public JWTClaimsSet() {
	
		// Nothing to do
	}
	
	
	/**
	 * Gets the reserved JWT claim names.
	 *
	 * @return The reserved claim names, as an unmodifiable set.
	 */
	public static Set<String> getReservedNames() {
	
		return RESERVED_CLAIM_NAMES;
	}


	@Override
	public String getIssuer() {
	
		return iss;
	}
	
	
	/**
	 * Sets the issuer ({@code iss}) claim.
	 *
	 * @param iss The issuer claim, {@code null} if not specified.
	 */
	public void setIssuer(final String iss) {
	
		this.iss = iss;
	}


	@Override
	public String getSubject() {
	
		return sub;
	}
	
	
	/**
	 * Sets the subject ({@code sub}) claim.
	 *
	 * @param sub The subject claim, {@code null} if not specified.
	 */
	public void setSubject(final String sub) {
	
		this.sub = sub;
	}
	
	
	@Override
	public List<String> getAudience() {
	
		return aud;
	}
	
	
	/**
	 * Sets the audience ({@code aud}) clam.
	 *
	 * @param aud The audience claim, {@code null} if not specified.
	 */
	public void setAudience(final List<String> aud) {
	
		this.aud = aud;
	}
	
	
	@Override
	public Date getExpirationTime() {
	
		return exp;
	}
	
	
	/**
	 * Sets the expiration time ({@code exp}) claim.
	 *
	 * @param exp The expiration time, {@code null} if not specified.
	 */
	public void setExpirationTime(final Date exp) {
	
		this.exp = exp;
	}
	
	
	@Override
	public Date getNotBeforeTime() {
	
		return nbf;
	}
	
	
	/**
	 * Sets the not-before ({@code nbf}) claim.
	 *
	 * @param nbf The not-before claim, {@code null} if not specified.
	 */
	public void setNotBeforeTime(final Date nbf) {
	
		this.nbf = nbf;
	}
	
	
	@Override
	public Date getIssueTime() {
	
		return iat;
	}
	
	
	/**
	 * Sets the issued-at ({@code iat}) claim.
	 *
	 * @param iat The issued-at claim, {@code null} if not specified.
	 */
	public void setIssueTime(final Date iat) {
	
		this.iat = iat;
	}
	
	
	@Override
	public String getJWTID() {
	
		return jti;
	}
	
	
	/**
	 * Sets the JWT ID ({@code jti}) claim.
	 *
	 * @param jti The JWT ID claim, {@code null} if not specified.
	 */
	public void setJWTID(final String jti) {
	
		this.jti = jti;
	}
	
	
	@Override
	public String getType() {
	
		return typ;
	}
	
	
	/**
	 * Sets the type ({@code typ}) claim.
	 *
	 * @param typ The type claim, {@code null} if not specified.
	 */
	public void setType(final String typ) {
	
		this.typ = typ;
	}
	
	
	@Override
	public Object getCustomClaim(final String name) {
	
		return customClaims.get(name);
	}
	
	
	/**
	 * Sets a custom (non-reserved) claim.
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

		if (iss != null)
			o.put("iss", iss);

		if (sub != null)
			o.put("sub", sub);
		
		if (aud != null) {
			JSONArray audArray = new JSONArray();
			audArray.addAll(aud);
			o.put("aud", audArray);
		}
		
		if (exp != null)
			o.put("exp", exp.getTime());
		
		if (nbf != null)
			o.put("nbf", nbf.getTime());
			
		if (iat != null)
			o.put("iat", iat.getTime());
		
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
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If the specified JSON object doesn't represent
	 *                        a valid JWT claims set.
	 */
	public static JWTClaimsSet parse(final JSONObject json)
		throws ParseException {
	
		JWTClaimsSet cs = new JWTClaimsSet();
	
		// Parse reserved + custom params
		for (final String name: json.keySet()) {

			if (name.equals("iss")) {

				cs.setIssuer(JSONObjectUtils.getString(json, "iss"));
			}
			else if (name.equals("sub")) {

				cs.setSubject(JSONObjectUtils.getString(json, "sub"));
			}
			else if (name.equals("aud")) {

				Object audValue = json.get("aud");

				if (audValue != null && audValue instanceof String) {
					List<String> singleAud = new ArrayList<String>();
					singleAud.add(JSONObjectUtils.getString(json, "aud"));
					cs.setAudience(singleAud);
				}
				else {
					cs.setAudience(JSONObjectUtils.getStringList(json, "aud"));
				}
			}
			else if (name.equals("exp")) {
				
				cs.setExpirationTime(new Date(JSONObjectUtils.getLong(json, "exp")));
			}
			else if (name.equals("nbf")) {
				
				cs.setNotBeforeTime(new Date(JSONObjectUtils.getLong(json, "nbf")));
			}
			else if (name.equals("iat")) {
				
				cs.setIssueTime(new Date(JSONObjectUtils.getLong(json, "iat")));
			}
			else if (name.equals("jti")) {
				
				cs.setJWTID(JSONObjectUtils.getString(json, "jti"));
			}
			else if (name.equals("typ")) {

				cs.setType(JSONObjectUtils.getString(json, "typ"));
			}
			else {
				cs.setCustomClaim(name, json.get(name));
			}
		}
		
		return cs;
	}
}
