package com.nimbusds.jose;


import java.util.Set;


/**
 * JSON Web Signature (JWS) verifier or JSON Web Encryption (JWE) decrypter
 * that supports processing and / or deferral of critical ({@code crit}) header
 * parameters.
 *
 * <p>JWS verification / JWE decryption will fail with a {@link JOSEException}
 * if a critical header is encountered that is neither processed by the
 * verifier / decrypter nor deferred to the application.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-21
 */
public interface CriticalHeaderParamsAware {


	/**
	 * Returns the names of the critical ({@code crit}) header parameters
	 * that are understood and processed by the JWS verifier / JWE
	 * decrypter.
	 *
	 * @return The names of the critical header parameters that are
	 *         understood and processed, empty set if none.
	 */
	Set<String> getProcessedCriticalHeaderParams();


	/**
	 * Returns the names of the critical ({@code crit}) header parameters
	 * that are deferred to the application for processing and will be
	 * ignored by the JWS verifier / JWE decrypter.
	 *
	 * @return The names of the critical header parameters that are
	 *         deferred to the application for processing, empty set if
	 *         none.
	 */
	Set<String> getDeferredCriticalHeaderParams();
}
