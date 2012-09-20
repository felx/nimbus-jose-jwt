package com.nimbusds.jose;


import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import net.minidev.json.JSONObject;

import com.nimbusds.util.Base64URL;


/**
 * Plain header.
 *
 * <p>Supports all reserved header parameters of the plain specification:
 *
 * <ul>
 *     <li>alg (set to {@link Algorithm#NONE "none"}).
 *     <li>typ
 *     <li>cty
 * </ul>
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the reserved ones.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "alg" : "none"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public class PlainHeader extends Header implements ReadOnlyPlainHeader {


	/**
	 * Creates a new plain header.
	 */
	public PlainHeader() {
	
		super(Algorithm.NONE);
	}
	
	
	
	@Override
	public Algorithm getAlgorithm() {
	
		return alg;
	}
	
	
	/**
	 * Parses a plain header from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON object doesn't represent
	 *                        a valid plain header.
	 */
	public static PlainHeader parse(final JSONObject json)
		throws ParseException {
		
		if (json == null)
			throw new ParseException("The JSON object must not be null");
		
		
		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(json);
		
		if (alg != Algorithm.NONE)
			throw new ParseException("The algorithm \"alg\" header parameter must be \"none\"");
			
		
		// Create a minimal header, type may be set later
		PlainHeader h = new PlainHeader();
		
		
		// Parse optional + custom parameters
		Map<String,Object> customParameters = new HashMap<String,Object>();
		
		Iterator<Map.Entry<String,Object>> it = json.entrySet().iterator();
		
		while (it.hasNext()) {
		
			Map.Entry<String,Object> entry = it.next();
			String name = entry.getKey();
			Object value = entry.getValue();
			
			if (value == null)
				continue;
				
			else if (name.equals("alg"))
				continue;
				
			else if (name.equals("typ"))
				h.setType(Header.parseType(json));
				
			else if (name.equals("cty"))
				h.setContentType(Header.parseContentType(json));
				
			else
				customParameters.put(name, value);
		}
		
		if (! customParameters.isEmpty())
			h.setCustomParameters(customParameters);
		
		return h;
	}
	
	
	/**
	 * Parses a plain header from the specified JSON string.
	 *
	 * @param s The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON string doesn't represent
	 *                        a valid plain header.
	 */
	public static PlainHeader parse(final String s)
		throws ParseException {
		
		JSONObject json = Header.parseHeaderJSON(s);
		
		return parse(json);
	}
	
	
	/**
	 * Parses a plain header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent a
	 *                        valid plain header.
	 */
	public static PlainHeader parse(final Base64URL base64URL)
		throws ParseException {
		
		if (base64URL == null)
			throw new ParseException("The Base64URL must not be null");
			
		return parse(base64URL.decodeToString());
	}
}
