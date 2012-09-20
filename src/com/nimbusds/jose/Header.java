package com.nimbusds.jose;


import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import com.nimbusds.util.Base64URL;


/**
 * The base abstract class for plain, JSON Web Signature (JWS) and JSON Web 
 * Encryption (JWE) headers.
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the reserved ones.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public abstract class Header implements ReadOnlyHeader {
	
	
	/**
	 * The algorithm ({@code alg}) parameter.
	 */
	final protected Algorithm alg;
	
	
	/**
	 * The JOSE object type ({@code typ}) parameter.
	 */
	private JOSEObjectType typ;
	
	
	/**
	 * The content type ({@code cty}) parameter.
	 */
	private String cty;
	
	
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
	
		if (alg == null)
			throw new IllegalArgumentException("The algorithm \"alg\" header parameter must not be null");
		
		this.alg = alg;
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
	public String getContentType() {
	
		return cty;
	}
	
	
	/**
	 * Sets the content type ({@code cty}) parameter.
	 *
	 * @param cty The content type parameter, {@code null} if not specified.
	 */
	public void setContentType(final String cty) {
	
		this.cty = cty;
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
		
		if (cty != null)
			o.put("cty", cty);
		
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
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JSON object.
	 *
	 * @throws ParseException If the specified string couldn't be parsed to 
	 *                        a JSON object.
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
	 * <p>The algorithm type (none, JWS or JWE) is determined by inspecting
	 * the algorithm name for "none" and the presence of an "enc" parameter.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The algorithm, an instance of {@link Algorithm#NONE},
	 *         {@link JWSAlgorithm} or {@link JWEAlgorithm}.
	 *
	 * @throws ParseException If the {@code alg} parameter couldn't be 
	 *                        parsed.
	 */
	protected static Algorithm parseAlgorithm(final JSONObject json)
		throws ParseException {
		
		if (! json.containsKey("alg") || json.get("alg") == null)
			throw new ParseException("Missing algorithm \"alg\" header parameter");
		
		if (! (json.get("alg") instanceof String))
			throw new ParseException("Invalid algorithm \"alg\" header parameter: Must be string");
		
		String algName = (String)json.get("alg");
		
		
		// Infer algorithm type
		
		// Plain
		if (algName.equals(Algorithm.NONE.getName()))
			return Algorithm.NONE;
		
		// JWE
		else if (json.containsKey("enc"))
			return JWEAlgorithm.parse(algName);
		
		// JWS
		else
			return JWSAlgorithm.parse(algName);
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
		
			throw new ParseException("Invalid type \"typ\" header parameter: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a content type ({@code cty}) parameter from the specified 
	 * header JSON object. Intended for initial parsing of plain, JWS and 
	 * JWE headers.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The content type, {@code null} if not specified.
	 *
	 * @throws ParseException If the {@code cty} parameter couldn't be
	 *                        parsed.
	 */
	protected static String parseContentType(final JSONObject json)
		throws ParseException {
		
		if (! json.containsKey("cty"))
			return null;
		
		try {
			return (String)json.get("cty");
			
		} catch (Exception e) {
		
			throw new ParseException("Invalid content type \"cty\" header parameter: " + e.getMessage(), e);
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
		
		Algorithm alg = parseAlgorithm(json);
		
		if (alg.equals(Algorithm.NONE))
			return PlainHeader.parse(json);
			
		else if (alg instanceof JWSAlgorithm)
			return JWSHeader.parse(json);
			
		else if (alg instanceof JWEAlgorithm)
			return JWEHeader.parse(json);
		
		else
			throw new AssertionError("Unknown algorithm type: " + alg);
	}
}
