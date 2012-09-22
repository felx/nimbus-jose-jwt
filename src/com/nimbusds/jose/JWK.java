package com.nimbusds.jose;


import java.text.ParseException;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.util.JSONObjectUtils;


/**
 * The base abstract class for public JSON Web Keys (JWKs). It serialises to a 
 * JSON object.
 *
 * <p>The following JSON object members are common to all JWK types:
 *
 * <ul>
 *     <li>{@link #getAlgorithmFamily alg} (required)
 *     <li>{@link #getKeyUse use} (optional)
 *     <li>{@link #getKeyID kid} (optional)
 * </ul>
 *
 * <p>Example JWK (of the Elliptic Curve type):
 *
 * <pre>
 * { 
 *   "alg" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-22)
 */
public abstract class JWK implements JSONAware {
	
	
	/**
	 * The algorithm family, required.
	 */
	private final AlgorithmFamily alg;
	
	
	/**
	 * The use, optional.
	 */
	private final Use use;
	
	
	/**
	 * The key ID, optional.
	 */
	private final String kid;
	
	
	/**
	 * Creates a new JSON Web Key (JWK) with the specified parameters.
	 *
	 * @param alg The JOSE algorithm family. Must not be {@code null}.
	 * @param use The key use, {@code null} if not specified or if the key 
	 *            is intended for signing as well as encryption.
	 * @param kid The key ID, {@code null} if not specified.
	 */
	public JWK(final AlgorithmFamily alg, final Use use, final String kid) {
	
		if (alg == null)
			throw new IllegalArgumentException("The algorithm family \"alg\" must not be null");
		
		this.alg = alg;
		
		this.use = use;
		
		this.kid = kid;
	}
	
	
	/**
	 * Gets the JOSE algorithm family ({@code alg}) of this JWK.
	 *
	 * @return The JOSE algorithm family.
	 */
	public AlgorithmFamily getAlgorithmFamily() {
	
		return alg;
	}
	
	
	/**
	 * Gets the use ({@code use}) of this JWK.
	 *
	 * @return The key use, {@code null} if not specified or if the key is
	 *         intended for signing as well as encryption.
	 */
	public Use getKeyUse() {
	
		return use;
	}
	
	
	/**
	 * Gets the ID ({@code kid}) of this JWK. The key ID can be used to 
	 * match a specific key. This can be used, for instance, to choose a key
	 * within a {@link JWKSet} during key rollover. The key ID may also 
	 * correspond to a JWS/JWE {@code kid} header parameter value.
	 *
	 * @return The key ID, {@code null} if not specified.
	 */
	public String getKeyID() {
	
		return kid;
	}
	
	
	/**
	 * Returns a JSON object representation of this JWK. This method is 
	 * intended to be called from extending classes.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "alg" : "RSA",
	 *   "use" : "sig",
	 *   "kid" : "fd28e025-8d24-48bc-a51a-e2ffc8bc274b"
	 * }
	 * </pre>
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
	
		o.put("alg", alg.toString());
		
		if (use != null) {
		
			if (use == Use.SIGNATURE)
				o.put("use", "sig");
			
			if (use == Use.ENCRYPTION)
				o.put("use", "enc");
		}
			
		if (kid != null)
			o.put("kid", kid);
	
		return o;
	}
	
	
	/**
	 * Returns the JSON object string representation of this JWK.
	 *
	 * @return The JSON object string representation.
	 */
	@Override
	public String toJSONString() {
	
		return toJSONObject().toString();
	}
	
	
	/**
	 * @see #toJSONString
	 */
	@Override
	public String toString() {
	
		return toJSONObject().toString();
	}
	
	
	/**
	 * Parses a JWK from the specified JSON object string representation. 
	 * The JWK must be an {@link ECKey} or an {@link RSAKey}.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The JWK.
	 *
	 * @throws ParseException If the string couldn't be parsed to valid and
	 *                        supported JWK.
	 */
	public static JWK parse(final String s)
		throws ParseException {
		
		return parse(JSONObjectUtils.parseJSONObject(s));
	}
	
	
	/**
	 * Parses a JWK from the specified JSON object representation. The JWK 
	 * must be an {@link ECKey} or an {@link RSAKey}.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        valid and supported JWK.
	 */
	public static JWK parse(final JSONObject jsonObject)
		throws ParseException {
		
		AlgorithmFamily alg = AlgorithmFamily.parse(JSONObjectUtils.getString(jsonObject, "alg"));
		
		if (alg == AlgorithmFamily.EC)
			return ECKey.parse(jsonObject);
		
		else if (alg == AlgorithmFamily.RSA)
			return RSAKey.parse(jsonObject);
			
		else
			throw new ParseException("Unsupported algorithm family \"alg\" parameter: " + alg, 0);
	}
	
	
	/**
	 * Parses a key use ({@code use}) parameter from the specified JSON 
	 * object representation of a JWK.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key use, {@code null} if not specified.
	 *
	 * @throws ParseException If the key use parameter couldn't be parsed.
	 */
	protected static Use parseKeyUse(final JSONObject jsonObject)
		throws ParseException {
		
		if (jsonObject.get("use") == null)
			return null;

		String useStr = JSONObjectUtils.getString(jsonObject, "use");

		if (useStr.equals("sig"))
			return Use.SIGNATURE;
			
		else if (useStr.equals("enc"))
			return Use.ENCRYPTION;
		
		else
			throw new ParseException("Invalid or unsupported key use \"use\" parameter, must be \"sig\" or \"enc\"", 0);
	}
	
	
	/**
	 * Parses a key ID ({@code kid}) parameter from the specified JSON
	 * object representation of a JWK.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key ID, {@code null} if not specified.
	 *
	 * @throws ParseException if the key ID parameter couldn't be parsed.
	 */
	protected static String parseKeyID(final JSONObject jsonObject)
		throws ParseException {
		
		if (jsonObject.get("kid") == null)
			return null;

		return JSONObjectUtils.getString(jsonObject, "kid");
	}
}
