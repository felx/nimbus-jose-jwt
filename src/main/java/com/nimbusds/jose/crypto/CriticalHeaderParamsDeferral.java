package com.nimbusds.jose.crypto;


import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.Header;


/**
 * Critical ({@code crit}) header parameters deferral policy.
 *
 * @see CriticalHeaderParamsAware
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-21)
 */
class CriticalHeaderParamsDeferral {


	/**
	 * The names of the deferred critical headers.
	 */
	private Set<String> deferredParams = Collections.emptySet();


	/**
	 * Returns the names of the critical ({@code crit}) header parameters
	 * that are understood and processed.
	 *
	 * @return Empty immutable set.
	 */
	public Set<String> getProcessedCriticalHeaderParams() {

		return Collections.emptySet();
	}


	/**
	 * Returns the names of the critical ({@code crit}) header parameters
	 * that are deferred to the application for processing.
	 *
	 * @return The names of the critical header parameters that are
	 *         deferred to the application for processing, as an
	 *         unmodifiable set, empty set if none.
	 */
	public Set<String> getDeferredCriticalHeaderParams() {

		return Collections.unmodifiableSet(deferredParams);
	}


	/**
	 * Sets the names of the critical ({@code crit}) header parameters
	 * that are deferred to the application for processing.
	 *
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 */
	public void setDeferredCriticalHeaderParams(final Set<String> defCritHeaders) {

		if (defCritHeaders == null) {
			this.deferredParams = Collections.emptySet();
		} else {
			this.deferredParams = defCritHeaders;
		}
	}


	/**
	 * Returns {@code true} if the specified header passes the critical
	 * parameters check.
	 *
	 * @param header The JWS or JWE header to check. Must not be
	 *               {@code null}.
	 *
	 * @return {@code true} if the header passes, {@code false} if the
	 *         header contains one or more critical header parameters which
	 *         are not marked for deferral to the application.
	 */
	public boolean headerPasses(final Header header) {

		Set<String> crit = header.getCriticalParams();

		if (crit == null || crit.isEmpty()) {
			return true; // OK
		}

		// Ensure all marked as deferred
		return deferredParams != null && deferredParams.containsAll(crit);
	}
}
