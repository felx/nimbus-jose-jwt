package com.nimbusds.jose.proc;


import java.security.Key;
import java.util.List;

import com.nimbusds.jose.JWSHeader;


/**
 * Interface for selecting key candidates for verifying a JSON Web Signature
 * (JWS) object. Applications should utilise this interface or a similar
 * framework to determine whether a received JWS object (or signed JWT) is
 * eligible for {@link com.nimbusds.jose.JWSVerifier verification} and further
 * processing.
 *
 * <p>The key selection should be based on application specific criteria, such
 * as recognised header parameters referencing the key (e.g. {@code kid},
 * {@code x5t}) and / or the JWS object {@link SecurityContext}.
 *
 * <p>See JSON Web Signature (JWS), Appendix D. Notes on Key Selection for
 * suggestions.
 *
 * <p>Possible key types:
 *
 * <ul>
 *     <li>{@link javax.crypto.SecretKey} for HMAC keys.
 *     <li>{@link java.security.interfaces.RSAPublicKey} public RSA keys.
 *     <li>{@link java.security.interfaces.ECPublicKey} public EC keys.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-08
 */
public interface JWSKeySelector<C extends SecurityContext>  {


	/**
	 * Selects key candidates for verifying a JWS object.
	 *
	 * @param header  The header of the JWS object. Must not be
	 *                {@code null}.
	 * @param context Optional context of the JWS object, {@code null} if
	 *                not required.
	 *
	 * @return The key candidates in trial order, empty list if none.
	 */
	List<? extends Key> selectJWSKeys(final JWSHeader header, final C context);
}
