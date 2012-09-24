package com.nimbusds.jose;


import java.net.MalformedURLException;
import java.net.URL;

import java.text.ParseException;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.util.Base64URL;
import com.nimbusds.util.JSONObjectUtils;


/**
 * JSON Web Signature (JWS) header.
 *
 * <p>Supports all {@link #getReservedParameterNames reserved header parameters}
 * of the JWS specification:
 *
 * <ul>
 *     <li>alg
 *     <li>jku
 *     <li>jwk
 *     <li>x5u
 *     <li>x5t
 *     <li>x5c
 *     <li>kid
 *     <li>typ
 *     <li>cty
 * </ul>
 *
 * <p>The header may also carry {@link #setCustomParameters custom parameters};
 * these will be serialised and parsed along the reserved ones.
 *
 * <p>Example header of a JSON Web Signature (JWS) object using the 
 * {@link JWSAlgorithm#HS256 HMAC SHA-256 algorithm}:
 *
 * <pre>
 * {
 *   "alg" : "HS256"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-24)
 */
public class JWSHeader extends CommonSEHeader implements ReadOnlyJWSHeader {


	/**
	 * The reserved parameter names.
	 */
	private static final Set<String> RESERVED_PARAMETER_NAMES;
	
	
	/**
	 * Initialises the reserved parameter name set.
	 */
	static {
		Set<String> p = new HashSet<String>();
		
		p.add("alg");
		p.add("jku");
		p.add("jwk");
		p.add("x5u");
		p.add("x5t");
		p.add("x5c");
		p.add("kid");
		p.add("typ");
		p.add("cty");
		
		RESERVED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * Creates a new JSON Web Signature (JWS) header.
	 *
	 * @param alg The JWS algorithm. Must not be {@code null}.
	 */
	public JWSHeader(final JWSAlgorithm alg) {
	
		super(alg);
	}
	
	
	/**
	 * Gets the reserved parameter names for JWS headers.
	 *
	 * @return The reserved parameter names, as an unmodifiable set.
	 */
	public static Set<String> getReservedParameterNames() {
	
		return RESERVED_PARAMETER_NAMES;
	}
	
	
	@Override
	public JWSAlgorithm getAlgorithm() {
	
		return (JWSAlgorithm)alg;
	}
	
	
	/**
	 * Parses a JWS header from the specified JSON object.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWS header.
	 */
	public static JWSHeader parse(final JSONObject json)
		throws ParseException {
	
		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(json);
		
		if (! (alg instanceof JWSAlgorithm))
			throw new ParseException("The algorithm \"alg\" header parameter must be for signatures", 0);
		
		// Create a minimal header
		JWSHeader h = new JWSHeader((JWSAlgorithm)alg);
		
		
		// Parse optional + custom parameters
		Map<String,Object> customParameters = new HashMap<String,Object>();
		
		Iterator<Map.Entry<String,Object>> it = json.entrySet().iterator();
		
		while (it.hasNext()) {
		
			Map.Entry<String,Object> entry = it.next();
			String name = entry.getKey();
			Object value = entry.getValue();
			
			if (value == null)
				continue;
			
			try {
				if (name.equals("alg")) {
					// Skip
					continue;
				}
				else if (name.equals("typ")) {
				
					h.setType(Header.parseType(json));
				}
				else if (name.equals("cty")) {
					
					h.setContentType(Header.parseContentType(json));
				}
				else if (name.equals("jku")) {

					h.setJWKURL(new URL((String)value));
				}
				else if (name.equals("jwk")) {
				
					h.setJWK(JWK.parse((JSONObject)value));
				}
				else if (name.equals("x5u")) {

					h.setX509CertURL(new URL((String)value));
				}
				else if (name.equals("x5t")) {

					h.setX509CertThumbprint(new Base64URL((String)value));
				}
				else if (name.equals("x5c")) {
					
					h.setX509CertChain(CommonSEHeader.parseX509CertChain((JSONArray)value));
				}
				else if (name.equals("kid")) {
				
					h.setKeyID((String)value);
				}
				else {
					// Custom parameter
					customParameters.put(name, value);
				}
			
			} catch (ClassCastException e) {
			
				// All params
				throw new ParseException("Unexpected JSON type of the \"" + name + "\" header parameter: " + e.getMessage(), 0);
				
			} catch (MalformedURLException e) {
			
				// All URL params
				throw new ParseException("Invalid URL of the \"" + name + "\" header parameter: " + e.getMessage(), 0);
			}
		}
		
		if (! customParameters.isEmpty())
			h.setCustomParameters(customParameters);
		
		return h;
	}
	
	
	/**
	 * Parses a JWS header from the specified JSON string.
	 *
	 * @param s The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified JSON object string doesn't 
	 *                        represent a valid JWS header.
	 */
	public static JWSHeader parse(final String s)
		throws ParseException {
		
		JSONObject jsonObject = JSONObjectUtils.parseJSONObject(s);
		
		return parse(jsonObject);
	}
	
	
	/**
	 * Parses a JWS header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The JWS header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent a 
	 *                        valid JWS header.
	 */
	public static JWSHeader parse(final Base64URL base64URL)
		throws ParseException {
			
		return parse(base64URL.decodeToString());
	}
}
