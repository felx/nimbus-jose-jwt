package com.nimbusds.jose;


import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;


/**
 * JSON Web Key (JWK) set. Represented by a JSON object that contains an array
 * of {@link JWK JSON Web Keys} (JWKs) as the value of its "keys" member.
 *
 * <p>Additional members of the JWK Set JSON object are not supported.
 *
 * <p>Example JSON Web Key (JWK) set:
 *
 * <pre>
 * {"keys":
 *   [
 *     {"alg":"EC",
 *	"crv":"P-256",
 *	"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *	"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *	"use":"enc",
 *	"kid":"1"},
 *
 *     {"alg":"RSA",
 *	"mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 * 4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 * tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 * QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 * SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 * w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *	"exp":"AQAB",
 *	"kid":"2011-04-29"}
 *   ]
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-19)
 */
public class JWKSet {


	/**
	 * The JWK list.
	 */
	private List<JWK> keys = new LinkedList<JWK>();
	
	
	/**
	 * Creates a new empty JSON Web Key (JWK) set.
	 */
	public JWKSet() {
	
		// Nothing to do
	}
	
	
	/**
	 * Creates a new JSON Web Key (JWK) set with a single key.
	 *
	 * @param key The JWK. Must not be {@code null}.
	 */
	public JWKSet(final JWK key) {
	
		if (key == null)
			throw new IllegalArgumentException("The JWK must not be null");
		
		keys.add(key);
	}
	
	
	/**
	 * Creates a new JSON Web Key (JWK) set with the specified keys.
	 *
	 * @param keys The JWK keys. Must not be {@code null}.
	 */
	public JWKSet(final List<JWK> keys) {
	
		if (keys == null)
			throw new IllegalArgumentException("The JWK list must not be null");
		
		this.keys.addAll(keys);
	}
	
	
	/**
	 * Gets the keys (ordered) of this JSON Web Key (JWK) set.
	 *
	 * @return The keys, empty list if none.
	 */
	public List<JWK> getKeys() {
	
		return keys;
	}
	
	
	/**
	 * Returns a JSON object representation of this JSON Web Key (JWK) set.
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {
	
		JSONArray a = new JSONArray();
		
		Iterator <JWK> it = keys.iterator();
		
		while (it.hasNext())
			a.add(it.next().toJSONObject());
		
		JSONObject o = new JSONObject();
		
		o.put("keys", a);
		
		return o;
	}
	

	/**
	 * Returns the JSON object string representation of this JSON Web Key
	 * (JWK) set.
	 *
	 * @return The JSON object string representation.
	 */
	public String toString() {
	
		return toJSONObject().toString();
	}
	
	
	/**
	 * Parses the specified string representing a JSON Web Key (JWK) set.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JSON Web Key (JWK) set.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        JSON Web Key (JWK) set.
	 */
	public static JWKSet parse(final String s)
		throws ParseException {
	
		if (s == null)
			throw new ParseException("The parsed JSON string must not be null");
		
		try {
			JSONParser parser = new JSONParser(JSONParser.MODE_RFC4627);
			
			return parse((JSONObject)parser.parse(s));
			
		} catch (net.minidev.json.parser.ParseException e) {
		
			throw new ParseException("Invalid JSON: " + e.getMessage(), e);
		
		} catch (ClassCastException e) {
		
			throw new ParseException("The top level JSON entity must be an object");
		}
	}
	
	
	/**
	 * Parses the specified JSON object representing a JSON Web Key (JWK) 
	 * set.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JSON Web Key (JWK) set.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        JSON Web Key (JWK) set.
	 */
	public static JWKSet parse(final JSONObject json)
		throws ParseException {
		
		if (json == null)
			throw new ParseException("The JSON object must not be null");
		
		if (! json.containsKey("keys") || json.get("keys") == null)
			throw new ParseException("Missing or null \"keys\" member in the top level JSON object");
		
		JSONArray keyArray = null;
		
		try {
			keyArray = (JSONArray)json.get("keys");
			
		} catch (ClassCastException e) {
		
			throw new ParseException("The \"keys\" member must be a JSON array");
		}
		
		List<JWK> keys = new LinkedList<JWK>();
		
		for (int i=0; i < keyArray.size(); i++) {
		
			if (! (keyArray.get(i) instanceof JSONObject))
				throw new ParseException("The \"keys\" JSON array must contain JSON objects only");
			
			JSONObject keyJSON = (JSONObject)keyArray.get(i);
			
			try {
				keys.add(JWK.parse(keyJSON));
				
			} catch (ParseException e) {
			
				throw new ParseException("Invalid JWK at position " + i + ": " + e.getMessage(), e);
			}
		}
		
		return new JWKSet(keys);
	}
}
