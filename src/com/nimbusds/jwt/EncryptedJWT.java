package com.nimbusds.jwt;


import java.text.ParseException;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.sdk.JOSEObject;
import com.nimbusds.jose.sdk.Payload;
import com.nimbusds.jose.sdk.JWEHeader;
import com.nimbusds.jose.sdk.JWEObject;

import com.nimbusds.jose.sdk.util.Base64URL;


/**
 * Encrypted JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-28)
 */
public class EncryptedJWT extends JWEObject implements JWT {


	/**
	 * Creates a new to-be-encrypted JSON Web Token (JWT) with the specified
	 * header and claims set. The initial state will be 
	 * {@link com.nimbusds.jose.sdk.JWEObject.State#UNENCRYPTED unencrypted}.
	 *
	 * @param header    The JWE header. Must not be {@code null}.
	 * @param claimsSet The claims set. Must not be {@code null}.
	 */
	public EncryptedJWT(final JWEHeader header, ClaimsSet claimsSet) {
	
		super(header, new Payload(claimsSet.toJSONObject()));
	}
	
	
	/**
	 * Creates a new encrypted JSON Web Token (JWT) with the specified 
	 * serialised parts. The state will be 
	 * {@link com.nimbusds.jose.sdk.JWEObject.State#ENCRYPTED encrypted}.
	 *
	 * @param firstPart  The first part, corresponding to the JWE header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the encrypted 
	 *                   key. Empty or {@code null} if none.
	 * @param thirdPart  The third part, corresponding to the cipher text.
	 *                   Must not be {@code null}.
	 * @param fourthPart The fourth part, corresponding to the integrity
	 *                   value. Empty of {@code null} if none.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public EncryptedJWT(final Base64URL firstPart, 
	                    final Base64URL secondPart, 
			    final Base64URL thirdPart,
			    final Base64URL fourthPart)
		throws ParseException {
	
		super(firstPart, secondPart, thirdPart, fourthPart);
	}
	
	
	@Override
	public ReadOnlyClaimsSet getClaimsSet()
		throws ParseException {
		
		Payload payload = getPayload();
		
		if (payload == null)
			return null;
		
		JSONObject json = payload.toJSONObject();
		
		if (json == null)
			throw new ParseException("Payload of JWE object is not a valid JSON object", 0);
		
		return ClaimsSet.parse(json);
	}
	
	
	/**
	 * Parses an encrypted JSON Web Token (JWT) from the specified string in
	 * compact format. 
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The encrypted JWT.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        encrypted JWT.
	 */
	public static EncryptedJWT parse(final String s)
		throws ParseException {
		
		Base64URL[] parts = JOSEObject.split(s);
		
		if (parts.length != 4)
			throw new ParseException("Unexpected number of Base64URL parts, must be four", 0);
		
		return new EncryptedJWT(parts[0], parts[1], parts[2], parts[3]);
	}
}
