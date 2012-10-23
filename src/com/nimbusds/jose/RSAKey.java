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
 *   "mod" : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZC
 *            iFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5
 *            w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZg
 *            nYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt
 *            -bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIq
 *            bw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "xpo" : "AQAB",
 *   "kid" : "2012-09-18"
 * }
 * </pre>
 *
 * <p>See http://en.wikipedia.org/wiki/RSA_%28algorithm%29
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-23)
 */
@Immutable
public final class RSAKey extends JWK {
	
	
	/**
	 * The modulus value for the RSA public key.
	 */
	private final Base64URL mod;
	
	
	/**
	 * The exponent value for the RSA public key.
	 */
	private final Base64URL xpo;
	 
	
	/**
	 * Creates a new public RSA JSON Web Key (JWK) with the specified 
	 * parameters.
	 *
	 * @param mod The the modulus value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param xpo The exponent value for the RSA public key. It is 
	 *            represented as the Base64URL encoding of value's big 
	 *            endian representation. Must not be {@code null}.
	 * @param use The key use. {@code null} if not specified.
	 * @param kid The key ID. {@code null} if not specified.
	 */
	public RSAKey(final Base64URL mod, final Base64URL xpo, 
	              final Use use, final String kid) {
	
		super(AlgorithmFamily.RSA, use, kid);
		
		if (mod == null)
			throw new IllegalArgumentException("The modulus value must not be null");
		
		this.mod = mod;
		
		if (xpo == null)
			throw new IllegalArgumentException("The exponent value must not be null");
		
		this.xpo = xpo;
	}
	
	
	/**
	 * Returns the modulus value for this RSA public key. It is represented
	 * as the Base64URL encoding of the value's big ending representation.
	 *
	 * @return The RSA public key modulus.
	 */
	public Base64URL getModulus() {
	
		return mod;
	}
	
	
	/**
	 * Returns the exponent value for this RSA public key. It is represented
	 * as the Base64URL encoding of the value's big ending representation.
	 *
	 * @return The RSA public key exponent.
	 */
	public Base64URL getExponent() {
	
		return xpo;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
		
		// Append RSA public key specific attributes
		o.put("mod", mod.toString());
		o.put("xpo", xpo.toString());
	
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
		Base64URL mod = new Base64URL(JSONObjectUtils.getString(jsonObject, "mod"));
		Base64URL exp = new Base64URL(JSONObjectUtils.getString(jsonObject, "xpo"));
		
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
