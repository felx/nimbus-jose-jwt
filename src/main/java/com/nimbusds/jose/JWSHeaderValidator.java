package com.nimbusds.jose;


/**
 * JSON Web Signature (JWS) header validator.
 */
public interface JWSHeaderValidator {


	/**
	 * Validates the specified JWS header.
	 *
	 * @param jwsHeader The JWS header to validate. Must not be
	 *                  {@code null}.
	 *
	 * @throws JOSEException If the header is found to be invalid.
	 */
	public void validate(final JWSHeader jwsHeader)
		throws JOSEException;
}
