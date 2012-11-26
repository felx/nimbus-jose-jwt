package com.nimbusds.jose;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Public {@link AlgorithmFamily#RSA RSA} JSON Web Key (JWK). This class is 
 * immutable.
 *
 * <p>Example JSON:
 *
 * <pre>
 * { 
 *   "alg" : "RSA",
 *   "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *           4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *           tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *           QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *           SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *           w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "e"   : "AQAB",
 *   "kid" : "2011-04-29"}
 * }
 * </pre>
 *
 * <p>See http://en.wikipedia.org/wiki/RSA_%28algorithm%29
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-26)
 */
@Immutable
public final class RSAKey extends JWK {
	
	
	/**
	 * The modulus value for the RSA public key.
	 */
	private final Base64URL n;
	
	
	/**
	 * The exponent value for the RSA public key.
	 */
	private final Base64URL e;
	 
	
	/**
	 * Creates a new public RSA JSON Web Key (JWK) with the specified 
	 * parameters.
	 *
	 * @param n   The the modulus value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param e   The exponent value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param use The key use. {@code null} if not specified.
	 * @param kid The key ID. {@code null} if not specified.
	 */
	public RSAKey(final Base64URL n, final Base64URL e, 
	              final Use use, final String kid) {
	
		super(AlgorithmFamily.RSA, use, kid);
		
		if (n == null)
			throw new IllegalArgumentException("The modulus value must not be null");
		
		this.n = n;
		
		if (e == null)
			throw new IllegalArgumentException("The exponent value must not be null");
		
		this.e = e;
	}
	
	
	/**
	 * Returns the modulus value for this RSA public key. It is represented
	 * as the Base64URL encoding of the value's big ending representation.
	 *
	 * @return The RSA public key modulus.
	 */
	public Base64URL getModulus() {
	
		return n;
	}
	
	
	/**
	 * Returns the exponent value for this RSA public key. It is represented
	 * as the Base64URL encoding of the value's big ending representation.
	 *
	 * @return The RSA public key exponent.
	 */
	public Base64URL getExponent() {
	
		return e;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
		
		// Append RSA public key specific attributes
		o.put("n", n.toString());
		o.put("e", e.toString());
	
		return o;
	}
	
	
	/**
	 * Parses a public RSA JWK from the specified JSON object 
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The RSA Key.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to valid
	 *                        RSA JWK.
	 */
	public static RSAKey parse(final JSONObject jsonObject)
		throws ParseException {
		
		// Parse the mandatory parameters first
		AlgorithmFamily af = AlgorithmFamily.parse(JSONObjectUtils.getString(jsonObject, "alg"));
		Base64URL mod = new Base64URL(JSONObjectUtils.getString(jsonObject, "n"));
		Base64URL exp = new Base64URL(JSONObjectUtils.getString(jsonObject, "e"));
		
		// Get optional key use
		Use use = JWK.parseKeyUse(jsonObject);

		// Get optional key ID
		String id = JWK.parseKeyID(jsonObject);
		
		// Check alg family
		if (af != AlgorithmFamily.RSA)
			throw new ParseException("The algorithm family \"alg\" must be RSA", 0);
		
		return new RSAKey(mod, exp, use, id);
	}
}
