package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.ArrayList;
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
 * @author Justin Richer
 * @version $version$ (2013-02-21)
 */
public class JWTClaimsSet implements ReadOnlyJWTClaimsSet {

	
	private static final String TYPE_CLAIM = "typ";
	private static final String JWT_ID_CLAIM = "jti";
	private static final String ISSUED_AT_CLAIM = "iat";
	private static final String NOT_BEFORE_CLAIM = "nbf";
	private static final String EXPIRATION_TIME_CLAIM = "exp";
	private static final String AUDIENCE_CLAIM = "aud";
	private static final String SUBJECT_CLAIM = "sub";
	private static final String ISSUER_CLAIM = "iss";


    	/**
	 * The reserved claim names.
	 */
	private static final Set<String> RESERVED_CLAIM_NAMES;
	
	
	/**
	 * Initialises the reserved claim name set.
	 */
	static {
		Set<String> n = new HashSet<String>();
		
		n.add(ISSUER_CLAIM);
		n.add(SUBJECT_CLAIM);
		n.add(AUDIENCE_CLAIM);
		n.add(EXPIRATION_TIME_CLAIM);
		n.add(NOT_BEFORE_CLAIM);
		n.add(ISSUED_AT_CLAIM);
		n.add(JWT_ID_CLAIM);
		n.add(TYPE_CLAIM);
		
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
	 * Creates a copy of the specified JWT claims set.
	 *
	 * @param old The JWT claims set to copy. Must not be {@code null}.
	 */
	public JWTClaimsSet(final ReadOnlyJWTClaimsSet old) {
		super();
		setAllClaims(old.getAllClaims());
	}


	/* (non-Javadoc)
	 * @see java.lang.Object#clone()
	 */
	@Override
	protected Object clone() throws CloneNotSupportedException {
	
		// TODO Auto-generated method stub
		return super.clone();
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
	public Object getClaim(String name) {

		if (!getReservedNames().contains(name)) {

			return getCustomClaim(name);

		} else {
			// it's a reserved name, find out which one
			if (ISSUER_CLAIM.equals(name)) {
				return getIssuer();
			} else if (SUBJECT_CLAIM.equals(name)) {
				return getSubject();
			} else if (AUDIENCE_CLAIM.equals(name)) {
				return getAudience();
			} else if (EXPIRATION_TIME_CLAIM.equals(name)) {
				return getExpirationTime();
			} else if (NOT_BEFORE_CLAIM.equals(name)) {
				return getNotBeforeTime();
			} else if (ISSUED_AT_CLAIM.equals(name)) {
				return getIssueTime();
			} else if (JWT_ID_CLAIM.equals(name)) {
				return getJWTID();
			} else if (TYPE_CLAIM.equals(name)) {
				return getType();
			} else {
				// if we fall through down to here, something is wrong
				throw new IllegalArgumentException("Couldn't find reserved claim: " + name);
			}
		}
	}


	/**
	 * Sets the specified claim, whether reserved or custom.
	 *
	 * @param name  The name of the claim to set. Must not be {@code null}.
	 * @param value The value of the claim to set. May be {@code null}.
	 *
	 * @throws IllegalArgumentException If the claim is reserved and its
	 *                                  value is not of the expected type.
	 */
	public void setClaim(String name, Object value) {

		if (!getReservedNames().contains(name)) {
			setCustomClaim(name, value);
		} else {
			// it's a reserved name, find out which one
			if (ISSUER_CLAIM.equals(name)) {
				if (value instanceof String) {
					setIssuer((String)value);
				} else {
					throw new IllegalArgumentException("Issuer claim must be a String");
				}
			} else if (SUBJECT_CLAIM.equals(name)) {
				if (value instanceof String) {
					setSubject((String)value);
				} else {
					throw new IllegalArgumentException("Subject claim must be a String");
				}
			} else if (AUDIENCE_CLAIM.equals(name)) {
				if (value instanceof List<?>) {
					setAudience((List<String>)value);
				} else {
					throw new IllegalArgumentException("Audience claim must be a List<String>");
				}
			} else if (EXPIRATION_TIME_CLAIM.equals(name)) {
				if (value instanceof Date) {
					setExpirationTime((Date)value);
				} else {
					throw new IllegalArgumentException("Expiration claim must be a Date");
				}
			} else if (NOT_BEFORE_CLAIM.equals(name)) {
				if (value instanceof Date) {
					setNotBeforeTime((Date)value);
				} else {
					throw new IllegalArgumentException("Not-before claim must be a Date");
				}
			} else if (ISSUED_AT_CLAIM.equals(name)) {
				if (value instanceof Date) {
					setIssueTime((Date)value);
				} else {
					throw new IllegalArgumentException("Issued-at claim must be a Date");
				}
			} else if (JWT_ID_CLAIM.equals(name)) {
				if (value instanceof String) {
					setJWTID((String)value);
				} else {
					throw new IllegalArgumentException("JWT-ID claim must be a String");
				}
			} else if (TYPE_CLAIM.equals(name)) {
				if (value instanceof String) {
					setType((String)value);
				} else {
					throw new IllegalArgumentException("Type claim must be a String");
				}
			} else {
				// if we fall through down to here, something is wrong
				throw new IllegalArgumentException("Couldn't find reserved claim: " + name);
			}
		}
	}
    

	@Override
	public Map<String, Object> getAllClaims() {

		Map<String, Object> allClaims = new HashMap<String, Object>();
		
		allClaims.putAll(customClaims);
		
		for (String reservedClaim : RESERVED_CLAIM_NAMES) {

			allClaims.put(reservedClaim, getClaim(reservedClaim));
		}
		
		return Collections.unmodifiableMap(allClaims);
	}


	/** 
	 * Sets the claims of this JWT claims set, replacing any existing ones.
	 *
	 * @param newClaims The JWT claims. Must not be {@code null}.
	 */
	public void setAllClaims(Map<String, Object> newClaims) {
		
		for (String name : newClaims.keySet()) {
	        	setClaim(name, newClaims.get(name));
		}
	}
    
    
	@Override
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject(customClaims);

		if (iss != null)
			o.put(ISSUER_CLAIM, iss);

		if (sub != null)
			o.put(SUBJECT_CLAIM, sub);
		
		if (aud != null) {
			JSONArray audArray = new JSONArray();
			audArray.addAll(aud);
			o.put(AUDIENCE_CLAIM, audArray);
		}
		
		if (exp != null)
			o.put(EXPIRATION_TIME_CLAIM, exp.getTime());
		
		if (nbf != null)
			o.put(NOT_BEFORE_CLAIM, nbf.getTime());
			
		if (iat != null)
			o.put(ISSUED_AT_CLAIM, iat.getTime());
		
		if (jti != null)
			o.put(JWT_ID_CLAIM, jti);
		
		if (typ != null)
			o.put(TYPE_CLAIM, typ);
		
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

			if (name.equals(ISSUER_CLAIM)) {

				cs.setIssuer(JSONObjectUtils.getString(json, ISSUER_CLAIM));
			}
			else if (name.equals(SUBJECT_CLAIM)) {

				cs.setSubject(JSONObjectUtils.getString(json, SUBJECT_CLAIM));
			}
			else if (name.equals(AUDIENCE_CLAIM)) {

				Object audValue = json.get(AUDIENCE_CLAIM);

				if (audValue != null && audValue instanceof String) {
					List<String> singleAud = new ArrayList<String>();
					singleAud.add(JSONObjectUtils.getString(json, AUDIENCE_CLAIM));
					cs.setAudience(singleAud);
				}
				else {
					cs.setAudience(JSONObjectUtils.getStringList(json, AUDIENCE_CLAIM));
				}
			}
			else if (name.equals(EXPIRATION_TIME_CLAIM)) {
				
				cs.setExpirationTime(new Date(JSONObjectUtils.getLong(json, EXPIRATION_TIME_CLAIM)));
			}
			else if (name.equals(NOT_BEFORE_CLAIM)) {
				
				cs.setNotBeforeTime(new Date(JSONObjectUtils.getLong(json, NOT_BEFORE_CLAIM)));
			}
			else if (name.equals(ISSUED_AT_CLAIM)) {
				
				cs.setIssueTime(new Date(JSONObjectUtils.getLong(json, ISSUED_AT_CLAIM)));
			}
			else if (name.equals(JWT_ID_CLAIM)) {
				
				cs.setJWTID(JSONObjectUtils.getString(json, JWT_ID_CLAIM));
			}
			else if (name.equals(TYPE_CLAIM)) {

				cs.setType(JSONObjectUtils.getString(json, TYPE_CLAIM));
			}
			else {
				cs.setCustomClaim(name, json.get(name));
			}
		}
		
		return cs;
	}


	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {

		return "JWTClaimsSet [iss=" + iss + ", sub=" + sub + ", aud=" + aud + ", exp=" + exp + ", nbf=" + nbf + ", iat=" + iat + ", jti=" + jti + ", typ=" + typ + ", customClaims=" + customClaims + "]";
	}
}
