package com.nimbusds.jose;


import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import com.nimbusds.util.Base64URL;


/**
 * JSON Web Signature (JWS) header.
 *
 * <p>Supports all reserved header parameters of the JWS specification:
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
 * @version $version$ (2012-09-19)
 */
public class JWSHeader extends CommonSEHeader implements ReadOnlyJWSHeader {


	/**
	 * Creates a new JSON Web Signature (JWS) header.
	 *
	 * @param alg The JWS algorithm. Must not be {@code null}.
	 */
	public JWSHeader(final JWSAlgorithm alg) {
	
		super(alg);
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
	
		if (json == null)
			throw new ParseException("The JSON object must not be null");
		
		
		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(json);
		
		if (! (alg instanceof JWSAlgorithm))
			throw new ParseException("The algorithm \"alg\" header parameter must be for signatures");
		
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
				throw new ParseException("Unexpected JSON type of the \"" + name + "\" header parameter", e);
				
			} catch (MalformedURLException e) {
			
				// All URL params
				throw new ParseException("Invalid URL of the \"" + name + "\" header parameter", e);
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
		
		JSONObject json = Header.parseHeaderJSON(s);
		
		return parse(json);
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
		
		if (base64URL == null)
			throw new ParseException("The Base64URL must not be null");
			
		return parse(base64URL.decodeToString());
	}
}
