package com.nimbusds.jwt;


import com.nimbusds.jose.ParseException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;

import com.nimbusds.util.Base64URL;


/**
 * Encrypted JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-21)
 */
public class EncryptedJWT extends JWEObject implements JWT {


	/**
	 * Creates a new to-be-encrypted JSON Web Token (JWT) with the specified
	 * header and claims set. The initial state will be 
	 * {@link com.nimbusds.jose.JWEObject.State#UNENCRYPTED unencrypted}.
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
	 * {@link com.nimbusds.jose.JWEObject.State#ENCRYPTED encrypted}.
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
	public ClaimsSet getClaimsSet() {
	
		return null;
	}
}
