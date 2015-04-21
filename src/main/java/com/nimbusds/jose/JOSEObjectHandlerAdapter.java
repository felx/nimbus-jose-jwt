package com.nimbusds.jose;


/**
 * JOSE object handler adapter. Intended to be extended by classes that need
 * to handle only a subset of the JOSE object types.
 *
 * @author Vladimir Dzhuvinov
 * @since 3.4
 * @version $version$ (2014-11-18)
 */
public class JOSEObjectHandlerAdapter<T> implements JOSEObjectHandler<T> {


	@Override
	public T onPlainObject(final PlainObject plainObject) {
		return null;
	}


	@Override
	public T onJWSObject(final JWSObject jwsObject) {
		return null;
	}


	@Override
	public T onJWEObject(final JWEObject jweObject) {
		return null;
	}
}
