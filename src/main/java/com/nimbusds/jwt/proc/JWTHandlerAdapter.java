package com.nimbusds.jwt.proc;


import com.nimbusds.jose.proc.Context;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;


/**
 * JWT handler adapter. Intended to be extended by classes that need to handle
 * only a subset of the JWT types.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-22)
 */
public class JWTHandlerAdapter<T,C extends Context> implements JWTHandler<T,C> {


	@Override
	public T onPlainJWT(final PlainJWT plainJWT, final C context) {
		return null;
	}


	@Override
	public T onSignedJWT(final SignedJWT signedJWT, final C context) {
		return null;
	}


	@Override
	public T onEncryptedJWT(final EncryptedJWT encryptedJWT, final C context) {
		return null;
	}
}
