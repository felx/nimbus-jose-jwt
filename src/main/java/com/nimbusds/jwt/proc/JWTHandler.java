package com.nimbusds.jwt.proc;


import com.nimbusds.jose.handler.Context;
import com.nimbusds.jwt.*;


/**
 * Handler of parsed {@link JWT JSON Web Tokens} (JWT). Invoked by a
 * {@link JWTParser} after parsing a JWT to indicate its exact type -
 * {@link PlainJWT unsecured}, {@link SignedJWT signed} or
 * {@link EncryptedJWT encrypted}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-22)
 */
public interface JWTHandler<T, C extends Context> {


	/**
	 * Invoked when the {@link JWTParser} determines that the parsed JWT is
	 * unsecured (plain).
	 *
	 * @param plainJWT The parsed unsecured JWT. Not {@code null}.
	 * @param context  Optional context of the unsecured JWT, {@code null}
	 *                 if not required.
	 *
	 * @return Any object to be used after inspecting the JWT, or
	 *         {@code null} if no return value is necessary.
	 */
	T onPlainJWT(final PlainJWT plainJWT, final C context);


	/**
	 * Invoked when the {@link JWTParser} determines that the parsed JWT is
	 * signed (JWS).
	 *
	 * @param signedJWT The parsed signed JWT. Not {@code null}.
	 * @param context   Optional context of the signed JWT, {@code null}
	 *                  if not required.
	 *
	 * @return Any object to be used after inspecting the JWT, or
	 *         {@code null} if no return value is necessary.
	 */
	T onSignedJWT(final SignedJWT signedJWT, final C context);


	/**
	 * Invoked when the {@link JWTParser} determines that the parsed JWT is
	 * encrypted (JWE).
	 *
	 * @param encryptedJWT The parsed encrypted JWT. Not {@code null}.
	 * @param context      Optional context of the encrypted JWT,
	 *                     {@code null} if not required.
	 *
	 * @return Any object to be used after inspecting the JWT, or
	 *         {@code null} if no return value is necessary.
	 */
	T onEncryptedJWT(final EncryptedJWT encryptedJWT, final C context);
}
