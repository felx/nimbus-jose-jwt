package com.nimbusds.jwt;


/**
 * JWT handler adapter. Intended to be extended by classes that need to handle
 * only a subset of the JWT types.
 *
 * @author Vladimir Dzhuvinov
 * @since 3.4
 * @version $version$ (2014-11-18)
 */
public class JWTHandlerAdapter<T> implements JWTHandler<T> {


	@Override
	public T onPlainJWT(final PlainJWT plainJWT) {
		return null;
	}


	@Override
	public T onSignedJWT(final SignedJWT signedJWT) {
		return null;
	}


	@Override
	public T onEncryptedJWT(final EncryptedJWT encryptedJWT) {
		return null;
	}
}
