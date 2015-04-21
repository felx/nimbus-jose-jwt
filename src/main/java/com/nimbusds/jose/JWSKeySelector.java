package com.nimbusds.jose;


import java.security.Key;


/**
 * Created by vd on 15-4-20.
 */
public interface JWSKeySelector<T extends Key>  {


	/**
	 *
	 *
	 * @param header
	 * @param context
	 *
	 * @return
	 *
	 * @throws JOSEException
	 */
	T select(final JWSHeader header, final String context)
		throws JOSEException;
}
