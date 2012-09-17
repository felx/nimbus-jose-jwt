package com.nimbusds.jose;


import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import com.nimbusds.util.Base64URL;


/**
 * The base abstract class for plain, JWS and JWE headers.
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the reserved ones.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-17)
 */
public abstract class Header implements ReadOnlyHeader {
	
	
	/**
	 * The JOSE object type.
	 */
	private JOSEObjectType typ;
	
	
	/**
	 * The algorithm.
	 */
	private Algorithm alg;
	
	
	/**
	 * Custom header parameters.
	 */
	private Map<String,Object> customParameters = new HashMap<String,Object>();
	
	
	/**
	 * Creates a new header with the specified algorithm ({@code alg}) 
	 * parameter.
	 *
	 * @param alg The algorithm parameter. Must not be {@code null}.
	 */
	protected Header(final Algorithm alg) {
	
		setAlgorithm(alg);
	}
	
	
	@Override
	public JOSEObjectType getType() {
	
		return typ;
	}
	
	
	/**
	 * Sets the type ({@code typ}) parameter.
	 *
	 * @param typ The type parameter, {@code null} if not specified.
	 */
	public void setType(final JOSEObjectType typ) {
	
		this.typ = typ;
	}
	
	
	@Override
	public Algorithm getAlgorithm() {
	
		return alg;
	}
	
	
	/**
	 * Sets the algorithm ({@code alg}) parameter.
	 *
	 * @param alg The algorithm parameter. Must not be {@code null}.
	 */
	public void setAlgorithm(final Algorithm alg) {
	
		if (alg == null)
			throw new NullPointerException("The algorithm \"alg\" must not be null");
		
		this.alg = alg;
	}
	
	
	@Override
	public Map<String,Object> getCustomParameters() {
	
		return customParameters;
	}
	
	
	/**
	 * Sets the custom parameters. The values must be serialisable to a JSON
	 * entity, otherwise will be ignored.
	 *
	 * @param customParameters The custom parameters, empty map or 
	 *                         {@code null} if none.
	 */
	public void setCustomParameters(final Map<String,Object> customParameters) {
	
		if (customParameters == null)
			return;
			
		this.customParameters = customParameters;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
	
		// Include custom parameters, they will be overwritten if their
		// names match specified reserved ones
		JSONObject o = new JSONObject(customParameters);
	
		// Alg is always defined
		o.put("alg", alg.toString());
	
		if (typ != null)
			o.put("typ", typ.toString());
		
		return o;
	}
	
	
	/**
	 * Returns a JSON string representation of this header. All custom
	 * parameters will be included if they serialise to a JSON entity and 
	 * their names don't conflict with the reserved ones.
	 *
	 * @return The JSON string representation of this header.
	 */
	public String toString() {
	
		return toJSONObject().toString();
	}
	
	
	/**
	 * Returns a Base64URL representation of this header.
	 *
	 * @return The Base64URL representation of this header.
	 */
	public Base64URL toBase64URL() {
	
		return Base64URL.encode(toString());
	}
	
	
	/**
	 * Parses a header JSON object from the specified string. Intended for
	 * initial parsing of plain, JWS and JWE headers.
	 *
	 * @param s The string to parse, must not be {@code null}.
	 *
	 * @return The parsed JSON object.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a header.
	 */
	protected static JSONObject parseHeaderJSON(final String s)
		throws ParseException {
		
		if (s == null)
			throw new ParseException("The JSON string must not be null");
		
		JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);
		
		JSONObject json = null;
		
		try {
			json = (JSONObject)parser.parse(s);
			
		} catch (net.minidev.json.parser.ParseException e) {
		
			throw new ParseException("Invalid JSON: " + e.getMessage(), e);
			
		} catch (ClassCastException e) {
		
			throw new ParseException("The header must be a JSON object");
		}
		
		if (json == null)
			throw new ParseException("The header must be a JSON object");
		
		return json;
	}
	
	
	/**
	 * Parses an algorithm ({@code alg}) parameter from the specified 
	 * header JSON object. Intended for initial parsing of plain, JWS and 
	 * JWE headers.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The algorithm.
	 *
	 * @throws ParseException If the {@code alg} parameter couldn't be 
	 *                        parsed.
	 */
	protected static Algorithm parseAlgorithm(final JSONObject json)
		throws ParseException {
		
		if (! json.containsKey("alg") || json.get("alg") == null)
			throw new ParseException("Missing \"alg\" header parameter");
		
		if (! (json.get("alg") instanceof String))
			throw new ParseException("Invalid \"alg\" header parameter: Must be string");
		
		String algName = (String)json.get("alg");
		
		
		// Infer algorithm use
		Algorithm.Use use = Algorithm.Use.SIGNATURE;
		
		if (algName.equals(Algorithm.NONE.getName()))
			use = Algorithm.Use.NONE;
			
		else if (json.containsKey("enc"))
			use = Algorithm.Use.ENCRYPTION;
		
		
		return new Algorithm(algName, use);
	}
	
	
	/**
	 * Parses a type ({@code typ}) parameter from the specified header JSON
	 * object. Intended for initial parsing of plain, JWS and JWE headers.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The type, {@code null} if not specified.
	 *
	 * @throws ParseException If the {@code typ} parameter couldn't be
	 *                        parsed.
	 */
	protected static JOSEObjectType parseType(final JSONObject json)
		throws ParseException {
		
		if (! json.containsKey("typ"))
			return null;
		
		try {
			return new JOSEObjectType((String)json.get("typ"));
			
		} catch (Exception e) {
		
			throw new ParseException("Invalid \"typ\" header parameter: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader} 
	 * from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The header.
	 *
	 * @throws ParseException If the specified JSON object doesn't represent
	 *                        a valid header.
	 */
	public static Header parse(final JSONObject json)
		throws ParseException {
	
		if (json == null)
			throw new ParseException("The JSON object must not be null");
		
		
		// Get the "alg" mandatory parameter
		Algorithm alg = parseAlgorithm(json);
		
		switch (alg.getUse()) {
		
			case NONE:
				return PlainHeader.parse(json);
				
			case SIGNATURE:
				return JWSHeader.parse(json);
			
			case ENCRYPTION:
				return JWEHeader.parse(json);
			
			default:
				throw new AssertionError("Unknown algorithm use: " + alg.getUse());
		}
	}
}
