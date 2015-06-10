package com.nimbusds.jose.proc;


import java.security.Key;
import java.util.List;

import com.nimbusds.jose.JWEHeader;


/**
 * Interface for selecting the key candidates for decrypting a JSON Web
 * Encryption (JWS) object. Applications should utilise this interface or a
 * similar framework to determine whether a received JWE object (or encrypted
 * JWT) is eligible for {@link com.nimbusds.jose.JWEDecrypter decryption} and
 * further processing.
 *
 * <p>The key selection should be based on application specific criteria, such
 * as recognised header parameters referencing the key (e.g. {@code kid},
 * {@code x5t}) and / or the JWE object {@link SecurityContext}.
 *
 * <p>See JSON Web Signature (JWE), Appendix D. Notes on Key Selection for
 * suggestions.
 *
 * <p>Possible key types:
 *
 * <ul>
 *     <li>{@link javax.crypto.SecretKey} for AES keys.
 *     <li>{@link java.security.interfaces.RSAPrivateKey} private RSA keys.
 *     <li>{@link java.security.interfaces.ECPrivateKey} private EC keys.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-06-08)
 */
public interface JWEKeySelector <C extends SecurityContext> {


	/**
	 * Selects key candidates for decrypting a JWE object.
	 *
	 * @param header  The header of the JWE object. Must not be
	 *                {@code null}.
	 * @param context Optional context of the JWE object, {@code null} if
	 *                not required.
	 *
	 * @return The key candidates in trial order, empty list if none.
	 */
	List<? extends Key> selectJWEKeys(final JWEHeader header, final C context);
}
