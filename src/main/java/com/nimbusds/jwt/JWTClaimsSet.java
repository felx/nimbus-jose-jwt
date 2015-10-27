package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.*;

import net.jcip.annotations.Immutable;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * JSON Web Token (JWT) claims set. This class is immutable.
 *
 * <p>Supports all {@link #getRegisteredNames()}  registered claims} of the JWT
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
 * </ul>
 *
 * <p>The set may also contain custom claims; these will be serialised and
 * parsed along the registered ones.
 *
 * <p>Example JWT claims set:
 *
 * <pre>
 * {
 *   "sub"                        : "joe",
 *   "exp"                        : 1300819380,
 *   "http://example.com/is_root" : true
 * }
 * </pre>
 *
 * <p>Example usage:
 *
 * <pre>
 * JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
 *     .subject("joe")
 *     .expirationDate(new Date(1300819380 * 1000l)
 *     .claim("http://example.com/is_root", true)
 *     .build();
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2015-08-22
 */
@Immutable
public final class JWTClaimsSet {


	private static final String ISSUER_CLAIM = "iss";
	private static final String SUBJECT_CLAIM = "sub";
	private static final String AUDIENCE_CLAIM = "aud";
	private static final String EXPIRATION_TIME_CLAIM = "exp";
	private static final String NOT_BEFORE_CLAIM = "nbf";
	private static final String ISSUED_AT_CLAIM = "iat";
	private static final String JWT_ID_CLAIM = "jti";


	/**
	 * The registered claim names.
	 */
	private static final Set<String> REGISTERED_CLAIM_NAMES;


	/**
	 * Initialises the registered claim name set.
	 */
	static {
		Set<String> n = new HashSet<>();

		n.add(ISSUER_CLAIM);
		n.add(SUBJECT_CLAIM);
		n.add(AUDIENCE_CLAIM);
		n.add(EXPIRATION_TIME_CLAIM);
		n.add(NOT_BEFORE_CLAIM);
		n.add(ISSUED_AT_CLAIM);
		n.add(JWT_ID_CLAIM);

		REGISTERED_CLAIM_NAMES = Collections.unmodifiableSet(n);
	}


	/**
	 * Builder for constructing JSON Web Token (JWT) claims sets.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
	 *     .subject("joe")
	 *     .expirationDate(new Date(1300819380 * 1000l)
	 *     .claim("http://example.com/is_root", true)
	 *     .build();
	 * </pre>
	 */
	public static class Builder {


		/**
		 * The claims.
		 */
		private final Map<String,Object> claims = new LinkedHashMap<>();


		/**
		 * Creates a new builder.
		 */
		public Builder() {

			// Nothing to do
		}


		/**
		 * Creates a new builder with the claims from the specified
		 * set.
		 *
		 * @param jwtClaimsSet The JWT claims set to use. Must not be
		 *                     {@code null}.
		 */
		public Builder(final JWTClaimsSet jwtClaimsSet) {

			claims.putAll(jwtClaimsSet.claims);
		}


		/**
		 * Sets the issuer ({@code iss}) claim.
		 *
		 * @param iss The issuer claim, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder issuer(final String iss) {

			claims.put(ISSUER_CLAIM, iss);
			return this;
		}


		/**
		 * Sets the subject ({@code sub}) claim.
		 *
		 * @param sub The subject claim, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder subject(final String sub) {

			claims.put(SUBJECT_CLAIM, sub);
			return this;
		}


		/**
		 * Sets the audience ({@code aud}) claim.
		 *
		 * @param aud The audience claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder audience(final List<String> aud) {

			claims.put(AUDIENCE_CLAIM, aud);
			return this;
		}


		/**
		 * Sets a single-valued audience ({@code aud}) claim.
		 *
		 * @param aud The audience claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder audience(final String aud) {

			if (aud == null) {
				claims.put(AUDIENCE_CLAIM, null);
			} else {
				claims.put(AUDIENCE_CLAIM, Arrays.asList(aud));
			}
			return this;
		}


		/**
		 * Sets the expiration time ({@code exp}) claim.
		 *
		 * @param exp The expiration time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder expirationTime(final Date exp) {

			claims.put(EXPIRATION_TIME_CLAIM, exp);
			return this;
		}


		/**
		 * Sets the not-before ({@code nbf}) claim.
		 *
		 * @param nbf The not-before claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder notBeforeTime(final Date nbf) {

			claims.put(NOT_BEFORE_CLAIM, nbf);
			return this;
		}


		/**
		 * Sets the issued-at ({@code iat}) claim.
		 *
		 * @param iat The issued-at claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder issueTime(final Date iat) {

			claims.put(ISSUED_AT_CLAIM, iat);
			return this;
		}


		/**
		 * Sets the JWT ID ({@code jti}) claim.
		 *
		 * @param jti The JWT ID claim, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder jwtID(final String jti) {

			claims.put(JWT_ID_CLAIM, jti);
			return this;
		}


		/**
		 * Sets the specified claim (registered or custom).
		 *
		 * @param name  The name of the claim to set. Must not be
		 *              {@code null}.
		 * @param value The value of the claim to set, {@code null} if
		 *              not specified. Should map to a JSON entity.
		 *
		 * @return This builder.
		 */
		public Builder claim(final String name, final Object value) {

			claims.put(name, value);
			return this;
		}


		/**
		 * Builds a new JWT claims set.
		 *
		 * @return The JWT claims set.
		 */
		public JWTClaimsSet build() {

			return new JWTClaimsSet(claims);
		}
	}


	/**
	 * The claims map.
	 */
	private final Map<String,Object> claims = new LinkedHashMap<>();


	/**
	 * Creates a new JWT claims set.
	 *
	 * @param claims The JWT claims set as a map. Must not be {@code null}.
	 */
	private JWTClaimsSet(final Map<String,Object> claims) {
		
		this.claims.putAll(claims);
	}


	/**
	 * Gets the registered JWT claim names.
	 *
	 * @return The registered claim names, as a unmodifiable set.
	 */
	public static Set<String> getRegisteredNames() {

		return REGISTERED_CLAIM_NAMES;
	}


	/**
	 * Gets the issuer ({@code iss}) claim.
	 *
	 * @return The issuer claim, {@code null} if not specified.
	 */
	public String getIssuer() {

		try {
			return getStringClaim(ISSUER_CLAIM);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the subject ({@code sub}) claim.
	 *
	 * @return The subject claim, {@code null} if not specified.
	 */
	public String getSubject() {

		try {
			return getStringClaim(SUBJECT_CLAIM);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the audience ({@code aud}) clam.
	 *
	 * @return The audience claim, {@code null} if not specified.
	 */
	public List<String> getAudience() {

		List<String> aud;
		try {
			aud = getStringListClaim(AUDIENCE_CLAIM);
		} catch (ParseException e) {
			return null;
		}
		return aud != null ? Collections.unmodifiableList(aud) : null;
	}


	/**
	 * Gets the expiration time ({@code exp}) claim.
	 *
	 * @return The expiration time, {@code null} if not specified.
	 */
	public Date getExpirationTime() {

		try {
			return getDateClaim(EXPIRATION_TIME_CLAIM);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the not-before ({@code nbf}) claim.
	 *
	 * @return The not-before claim, {@code null} if not specified.
	 */
	public Date getNotBeforeTime() {

		try {
			return getDateClaim(NOT_BEFORE_CLAIM);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the issued-at ({@code iat}) claim.
	 *
	 * @return The issued-at claim, {@code null} if not specified.
	 */
	public Date getIssueTime() {

		try {
			return getDateClaim(ISSUED_AT_CLAIM);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the JWT ID ({@code jti}) claim.
	 *
	 * @return The JWT ID claim, {@code null} if not specified.
	 */
	public String getJWTID() {

		try {
			return getStringClaim(JWT_ID_CLAIM);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the specified claim (registered or custom).
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 */
	public Object getClaim(final String name) {

		return claims.get(name);
	}


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
	public String getStringClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null || value instanceof String) {
			return (String)value;
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a String", 0);
		}
	}


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
	public String[] getStringArrayClaim(final String name)
		throws ParseException {

		Object value = getClaim(name);

		if (value == null) {
			return null;
		}

		List<?> list;

		try {
			list = (List)getClaim(name);

		} catch (ClassCastException e) {
			throw new ParseException("The \"" + name + "\" claim is not a list / JSON array", 0);
		}

		String[] stringArray = new String[list.size()];

		for (int i=0; i < stringArray.length; i++) {

			try {
				stringArray[i] = (String)list.get(i);
			} catch (ClassCastException e) {
				throw new ParseException("The \"" + name + "\" claim is not a list / JSON array of strings", 0);
			}
		}

		return stringArray;
	}


	/**
	 * Gets the specified claims (registered or custom) as a
	 * {@link java.util.List} list of strings.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public List<String> getStringListClaim(final String name)
		throws ParseException {

		String[] stringArray = getStringArrayClaim(name);

		if (stringArray == null) {
			return null;
		}

		return Collections.unmodifiableList(Arrays.asList(stringArray));
	}


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
	public Boolean getBooleanClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null || value instanceof Boolean) {
			return (Boolean)value;
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Boolean", 0);
		}
	}


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
	public Integer getIntegerClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).intValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not an Integer", 0);
		}
	}


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
	public Long getLongClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).longValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Number", 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.util.Date}. The claim may be represented by a Date
	 * object or a number of a seconds since the Unix epoch.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Date getDateClaim(final String name)
		throws ParseException {

		Object value = getClaim(name);

		if (value == null) {
			return null;
		} else if (value instanceof Date) {
			return (Date)value;
		} else if (value instanceof Number) {
			return new Date(((Number)value).longValue() * 1000l);
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Date", 0);
		}
	}


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
	public Float getFloatClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).floatValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Float", 0);
		}
	}


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
	public Double getDoubleClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).doubleValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Double", 0);
		}
	}


	/**
	 * Gets the claims (registered and custom).
	 *
	 * <p>Note that the registered claims Expiration-Time ({@code exp}),
	 * Not-Before-Time ({@code nbf}) and Issued-At ({@code iat}) will be
	 * returned as {@code java.util.Date} instances.
	 *
	 * @return The claims, as an unmodifiable map, empty map if none.
	 */
	public Map<String,Object> getClaims() {

		return Collections.unmodifiableMap(claims);
	}


	/**
	 * Returns the JSON object representation of the claims set. The claims
	 * are serialised according to their insertion order.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		for (Map.Entry<String,Object> claim: claims.entrySet()) {

			if (claim.getValue() instanceof Date) {

				// Transform dates to Unix timestamps
				Date dateValue = (Date) claim.getValue();
				o.put(claim.getKey(), dateValue.getTime() / 1000);

			} else if (AUDIENCE_CLAIM.equals(claim.getKey())) {

				// Serialise single audience list and string
				List<String> audList = getAudience();

				if (audList != null && ! audList.isEmpty()) {
					if (audList.size() == 1) {
						o.put(AUDIENCE_CLAIM, audList.get(0));
					} else {
						JSONArray audArray = new JSONArray();
						audArray.addAll(audList);
						o.put(AUDIENCE_CLAIM, audArray);
					}
				}

			} else if (claim.getValue() != null) {
				// Do not output claims with null values!
				o.put(claim.getKey(), claim.getValue());
			}
		}

		return o;
	}


	@Override
	public String toString() {

		return toJSONObject().toJSONString();
	}


	/**
	 * Returns a transformation of this JWT claims set.
	 *
	 * @param <T> Type of the result.
	 * @param transformer The JWT claims set transformer. Must not be
	 *                    {@code null}.
	 *
	 * @return The transformed JWT claims set.
	 */
	public <T> T toType(final JWTClaimsSetTransformer<T> transformer) {

		return transformer.transform(this);
	}


	/**
	 * Parses a JSON Web Token (JWT) claims set from the specified JSON
	 * object representation.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWT claims set.
	 */
	public static JWTClaimsSet parse(final JSONObject json)
		throws ParseException {

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// Parse registered + custom params
		for (final String name: json.keySet()) {

			if (name.equals(ISSUER_CLAIM)) {

				builder.issuer(JSONObjectUtils.getString(json, ISSUER_CLAIM));

			} else if (name.equals(SUBJECT_CLAIM)) {

				builder.subject(JSONObjectUtils.getString(json, SUBJECT_CLAIM));

			} else if (name.equals(AUDIENCE_CLAIM)) {

				Object audValue = json.get(AUDIENCE_CLAIM);

				if (audValue instanceof String) {
					List<String> singleAud = new ArrayList<>();
					singleAud.add(JSONObjectUtils.getString(json, AUDIENCE_CLAIM));
					builder.audience(singleAud);
				} else if (audValue instanceof List) {
					builder.audience(JSONObjectUtils.getStringList(json, AUDIENCE_CLAIM));
				}

			} else if (name.equals(EXPIRATION_TIME_CLAIM)) {

				builder.expirationTime(new Date(JSONObjectUtils.getLong(json, EXPIRATION_TIME_CLAIM) * 1000));

			} else if (name.equals(NOT_BEFORE_CLAIM)) {

				builder.notBeforeTime(new Date(JSONObjectUtils.getLong(json, NOT_BEFORE_CLAIM) * 1000));

			} else if (name.equals(ISSUED_AT_CLAIM)) {

				builder.issueTime(new Date(JSONObjectUtils.getLong(json, ISSUED_AT_CLAIM) * 1000));

			} else if (name.equals(JWT_ID_CLAIM)) {

				builder.jwtID(JSONObjectUtils.getString(json, JWT_ID_CLAIM));

			} else {
				builder.claim(name, json.get(name));
			}
		}

		return builder.build();
	}


	/**
	 * Parses a JSON Web Token (JWT) claims set from the specified JSON
	 * object string representation.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If the specified JSON object string doesn't
	 *                        represent a valid JWT claims set.
	 */
	public static JWTClaimsSet parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(s));
	}
}
