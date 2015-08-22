package com.nimbusds.jwt.proc;


import com.nimbusds.jose.proc.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.proc.DefaultJWSVerifierFactory;
import com.nimbusds.jose.proc.JOSEProcessorConfiguration;
import com.nimbusds.jose.proc.SecurityContext;


/**
 * JWT processor configuration.
 *
 * <p></P>Specifies the required components to process JWTs:
 *
 * <ul>
 *     <li>To verify signed JWTs:
 *         <ul>
 *             <li>Key selector to determine key candidate(s) for JWS
 *                 verification based on the JWS header and application-
 *                 specific context information.
 *             <li>Factory to construct a JWS verifier for a given key
 *                 candidate and JWS header information. A
 *                 {@link DefaultJWSVerifierFactory default factory}
 *                 implementation is provided.
 *         </ul>
 *     <li>To decrypt encrypted JWTs:
 *         <ul>
 *             <li>Key selector to determine key candidate(s) for JWE
 *                 decryption based on the JWS header and application-specific
 *                 context information.
 *             <li>Factory to construct a JWE decrypter for a given key
 *                 candidate and JWE header information. A
 *                 {@link DefaultJWEDecrypterFactory default factory}
 *                 implementation is provided.
 *         </ul>
 *      <li>Optional JWT claims verifier. Intended to perform various
 *          application-specific JWT claims checks, such as token expiration
 *          and issuer acceptance, after successful JWS verification / JWE
 *          decryption.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-22
 */
public interface JWTProcessorConfiguration<C extends SecurityContext> extends JOSEProcessorConfiguration<C> {


	/**
	 * Gets the optional JWT claims verifier. Intended to perform various
	 * application-specific JWT claims checks, such as token expiration and
	 * issuer acceptance, after successful JWS verification / JWE decryption.
	 *
	 * @return The JWT claims verifier, {@code null} if not specified.
	 */
	JWTClaimsVerifier getJWTClaimsVerifier();


	/**
	 * Sets the optional JWT claims verifier. Intended to perform various
	 * application-specific JWT claims checks, such as token expiration and
	 * issuer acceptance, after successful JWS verification / JWE
	 * decryption.
	 *
	 * @param claimsVerifier The JWT claims verifier, {@code null} if not
	 *                       specified.
	 */
	void setJWTClaimsVerifier(final JWTClaimsVerifier claimsVerifier);
}
