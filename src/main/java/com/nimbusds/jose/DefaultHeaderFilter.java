package com.nimbusds.jose;


import java.util.Collections;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;


/**
 * Javascript Object Signing and Encryption (JOSE) header filter 
 * implementation. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-22)
 */
@ThreadSafe
public class DefaultHeaderFilter implements HeaderFilter {


	/**
	 * The accepted header parameters.
	 */
	private Set<String> acceptedParams;


	/**
	 * Creates a new JOSE header filter.
	 *
	 * @param acceptedParams The accepted header parameters. Must not be
	 *                       {@code null}.
	 */
	public DefaultHeaderFilter(final Set<String> acceptedParams) {

		setAcceptedParameters(acceptedParams);
	}


	@Override
	public Set<String> getAcceptedParameters() {

		return acceptedParams;
	}


	@Override
	public void setAcceptedParameters(final Set<String> acceptedParams) {

		if (acceptedParams == null) {

			throw new IllegalArgumentException("The accepted header parameters set must not be null");
		}

		this.acceptedParams = Collections.unmodifiableSet(acceptedParams);
	}
}
