package com.nimbusds.jose;


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

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


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
 * @version $version$ (2012-10-01)
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
	 * @throws IllegalArgumentException If the specified parameter name
	 *                                  matches a reserved parameter name.
	 */
	@Override
	public void setCustomParameter(final String name, final Object value) {
	
		if (getReservedParameterNames().contains(name))
			throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a reserved name");
		
		super.setCustomParameter(name, value);
	}
	
	
	@Override
	public Set<String> getIncludedParameters() {
	
		Set<String> includedParameters = 
			new HashSet<String>(getCustomParameters().keySet());
		
		includedParameters.add("alg");
		
		if (getType() != null)
			includedParameters.add("typ");
			
		if (getContentType() != null)
			includedParameters.add("cty");
		
		if (getJWKURL() != null)
			includedParameters.add("jku");
		
		if (getJWK() != null)
			includedParameters.add("jwk");
		
		if (getX509CertURL() != null)
			includedParameters.add("x5u");
		
		if (getX509CertThumbprint() != null)
			includedParameters.add("x5t");
		
		if (getX509CertChain() != null)
			includedParameters.add("x5c");
		
		if (getKeyID() != null)
			includedParameters.add("kid");
		
		return includedParameters;
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
		Iterator<String> it = json.keySet().iterator();
		
		while (it.hasNext()) {
		
			String name = it.next();
			
			if (name.equals("alg"))
				continue; // Skip
			
			else if (name.equals("typ"))
				h.setType(new JOSEObjectType(JSONObjectUtils.getString(json, name)));
			
			else if (name.equals("cty"))
				h.setContentType(JSONObjectUtils.getString(json, name));
			
			else if (name.equals("jku"))
				h.setJWKURL(JSONObjectUtils.getURL(json, name));
			
			else if (name.equals("jwk"))
				h.setJWK(JWK.parse(JSONObjectUtils.getJSONObject(json, name)));
			
			else if (name.equals("x5u"))
				h.setX509CertURL(JSONObjectUtils.getURL(json, name));
			
			else if (name.equals("x5t"))
				h.setX509CertThumbprint(new Base64URL(JSONObjectUtils.getString(json, name)));
			
			else if (name.equals("x5c"))
				h.setX509CertChain(CommonSEHeader.parseX509CertChain(JSONObjectUtils.getJSONArray(json, name)));
			
			else if (name.equals("kid"))
				h.setKeyID(JSONObjectUtils.getString(json, name));
			
			else
				h.setCustomParameter(name, json.get(name));
		}
		
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
