package com.nimbusds.jose.handler;


import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.PlainObject;


/**
 * JOSE object handler adapter. Intended to be extended by classes that need
 * to handle only a subset of the JOSE object types.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-22)
 */
public class JOSEObjectHandlerAdapter<T,C extends Context> implements JOSEObjectHandler<T,C> {


	@Override
	public T onPlainObject(final PlainObject plainObject, final C context) {
		return null;
	}


	@Override
	public T onJWSObject(final JWSObject jwsObject, final C context) {
		return null;
	}


	@Override
	public T onJWEObject(final JWEObject jweObject, final C context) {
		return null;
	}
}
