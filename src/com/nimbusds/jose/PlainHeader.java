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
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the supported ones.
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
 * @version $version$ (2012-09-17)
 */
public class PlainHeader extends Header implements ReadOnlyPlainHeader {


	/**
	 * Creates a new plain header.
	 */
	public PlainHeader() {
	
		super(Algorithm.NONE);
	}
	
	
	/**
	 * The algorithm of the plain header cannot be modified.
	 *
	 * @throws UnsupportedOperationException If this method is called.
	 */
	@Override
	public void setAlgorithm(final Algorithm alg) {
	
		throw new UnsupportedOperationException("The plain header algorithm cannot be modified");
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
			throw new ParseException("The \"alg\" parameter must be \"none\"");
			
		
		// Create a minimal header, type may be set later
		PlainHeader h = new PlainHeader();
		
		
		// Get the optional type parameter
		h.setType(Header.parseType(json));
		
		
		// Parse custom parameters
		Map<String,Object> customParameters = new HashMap<String,Object>();
		
		Iterator<Map.Entry<String,Object>> it = json.entrySet().iterator();
		
		while (it.hasNext()) {
		
			Map.Entry<String,Object> entry = it.next();
			String name = entry.getKey();
			Object value = entry.getValue();
			
			if (name.equals("alg") || name.equals("typ") || value == null)
				continue;
			
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
	 * @throws ParseException If the specified JSON object doesn't represent 
	 *                        a valid plain header.
	 */
	public static PlainHeader parse(final Base64URL base64URL)
		throws ParseException {
		
		if (base64URL == null)
			throw new ParseException("The Base64URL must not be null");
			
		return parse(base64URL.decodeToString());
	}
}
