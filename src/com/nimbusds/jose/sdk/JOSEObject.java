package com.nimbusds.jose.sdk;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.sdk.util.Base64URL;
import com.nimbusds.jose.sdk.util.JSONObjectUtils;


/**
 * The base abstract class for plain, JWS-secured and JWE-secured objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-24)
 */
public abstract class JOSEObject {


	/**
	 * The payload (message).
	 */
	private Payload payload;
	
	
	/**
	 * Creates a new JOSE object. The payload is not defined.
	 */
	protected JOSEObject() {
	
		payload = null;
	}
	
	
	/**
	 * Creates a new JOSE object with the specified payload.
	 *
	 * @param payload The payload, {@code null} if not available (e.g for an
	 *                encrypted JWE object).
	 */
	protected JOSEObject(final Payload payload) {
	
		this.payload = payload;
	}
	
	
	/**
	 * Sets the payload of this JOSE object.
	 *
	 * @param payload The payload, {@code null} if not available (e.g. for 
	 *                an encrypted JWE object).
	 */
	protected void setPayload(final Payload payload) {
	
		this.payload = payload;
	}
	
	
	/**
	 * Gets the payload of this JOSE object.
	 *
	 * @return The payload, {@code null} if not available (for an encrypted
	 *         JWE that isn't decrypted).
	 */
	public Payload getPayload() {
	
		return payload;
	}
	
	
	/**
	 * Serialises this JOSE object to its canonical compact format
	 * consisting of Base64URL-encoded parts delimited by period ('.') 
	 * characters.
	 *
	 * @return The serialised JOSE object.
	 *
	 * @throws JOSEException If the JOSE object is not in a state 
	 *                       permitting serialisation.
	 */
	public abstract String serialize()
		throws JOSEException;
	
	
	/**
	 * Splits a serialised JOSE object into its Base64URL-encoded parts.
	 *
	 * @param s The serialised JOSE object to split. Must not be 
	 *          {@code null}.
	 *
	 * @return The JOSE Base64URL-encoded parts (three for plain and JWS
	 *         objects, four for JWE objects).
	 *
	 * @throws ParseException If the specified string couldn't be split into
	 *                        three or four Base64URL-encoded parts.
	 */
	public static Base64URL[] split(final String s)
		throws ParseException {
		
		// We must have at least 2 dots but no more that 3
		
		// String.split() cannot handle empty parts
		final int dot1 = s.indexOf(".");
		
		if (dot1 == -1)
			throw new ParseException("Invalid serialized plain/JWS/JWE object: Missing part delimiters", 0);
			
		final int dot2 = s.indexOf(".", dot1 + 1);
		
		if (dot2 == -1)
			throw new ParseException("Invalid serialized plain/JWS/JWE object: Missing second delimiter", 0);
		
		// Third dot for JWE only
		final int dot3 = s.indexOf(".", dot2 + 1);
		
		if (dot3 != -1 && s.indexOf(".", dot3 + 1) != -1)
			throw new ParseException("Invalid serialized plain/JWS/JWE object: Too many part delimiters", 0);
		
		
		if (dot3 == -1) {
			// Two dots - > three parts
			Base64URL[] parts = new Base64URL[3];
			parts[0] = new Base64URL(s.substring(0, dot1));
			parts[1] = new Base64URL(s.substring(dot1 + 1, dot2));
			parts[2] = new Base64URL(s.substring(dot2 + 1));
			return parts;
		}
		else {
			// Three dots -> four parts
			Base64URL[] parts = new Base64URL[4];
			parts[0] = new Base64URL(s.substring(0, dot1));
			parts[1] = new Base64URL(s.substring(dot1 + 1, dot2));
			parts[2] = new Base64URL(s.substring(dot2 + 1, dot3));
			parts[3] = new Base64URL(s.substring(dot3 + 1));
			return parts;
		}
	}


	/**
	 * Parses a JOSE object.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The corresponding {@link PlainObject}, {@link JWSObject} or
	 *         {@link JWEObject} instance.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                       plain, JWS or JWE object.
	 */
	public static JOSEObject parse(final String s) 
		throws ParseException {
		
		Base64URL[] parts = split(s);
		
		JSONObject jsonObject = null;
		
 		try {
 			jsonObject = JSONObjectUtils.parseJSONObject(parts[0].decodeToString());
 			
 		} catch (ParseException e) {
 		
 			throw new ParseException("Invalid plain/JWS/JWE header: " + e.getMessage(), 0);
 		}
		
		Algorithm alg = Header.parseAlgorithm(jsonObject);

		if (alg.equals(Algorithm.NONE))
			return PlainObject.parse(s);
		
// 		switch (alg.getType()) {
// 		
// 			case NONE:
// 				return PlainJWT.parse(s);
// 				
// 			case SIGNATURE:
// 				return SignedJWT.parse(s);
// 				
// 			case ENCRYPTION:
// 				return EncryptedJWT.parse(s);
// 			
// 			default:
// 				throw new JOSEException("Couldn't determine algorithm type: " + alg);
// 		}
	
		return null;
	}
}
