package com.nimbusds.jwt;


/**
 * Handler of parsed {@link JWT JSON Web Tokens} (JWT). Invoked by a
 * {@link JWTParser} after parsing a JWT to indicate its exact type -
 * {@link PlainJWT plain}, {@link SignedJWT signed} or
 * {@link EncryptedJWT encrypted}.
 *
 * @since 3.4
 */
public interface JWTHandler<T> {


	/**
	 * Invoked when the {@link JWTParser} determines that the parsed JWT is
	 * plain (unsecured).
	 *
	 * @param plainJWT The parsed plain JWT. Not {@code null}.
	 *
	 * @return Any object to be used after inspecting the JWT, or
	 *         {@code null} if no return value is necessary.
	 */
	T onPlainJWT(final PlainJWT plainJWT);


	/**
	 * Invoked when the {@link JWTParser} determines that the parsed JWT is
	 * signed (JWS).
	 *
	 * @param signedJWT The parsed signed JWT. Not {@code null}.
	 *
	 * @return Any object to be used after inspecting the JWT, or
	 *         {@code null} if no return value is necessary.
	 */
	T onSignedJWT(final SignedJWT signedJWT);


	/**
	 * Invoked when the {@link JWTParser} determines that the parsed JWT is
	 * encrypted (JWE).
	 *
	 * @param encryptedJWT The parsed encrypted JWT. Not {@code null}.
	 *
	 * @return Any object to be used after inspecting the JWT, or
	 *         {@code null} if no return value is necessary.
	 */
	T onEncryptedJWT(final EncryptedJWT encryptedJWT);
}
