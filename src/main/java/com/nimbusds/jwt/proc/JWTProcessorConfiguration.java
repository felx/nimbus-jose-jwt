package com.nimbusds.jwt.proc;


import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
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
 *      <li>Optional JWT claims set verifier. Ensures that the claims set of a
 *          JWT complies with an application's requirements.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2016-07-25
 */
public interface JWTProcessorConfiguration<C extends SecurityContext> extends JOSEProcessorConfiguration<C> {


	/**
	 * Gets the optional JWT claims set verifier. Ensures that the claims
	 * set of a JWT complies with an application's requirements.
	 *
	 * @return The JWT claims set verifier, {@code null} if not specified.
	 */
	JWTClaimsSetVerifier<C> getJWTClaimsSetVerifier();


	/**
	 * Sets the optional JWT claims set verifier. Ensures that the claims
	 * set of a JWT complies with an application's requirements.
	 *
	 * @param claimsVerifier The JWT claims set verifier, {@code null} if
	 *                       not specified.
	 */
	void setJWTClaimsSetVerifier(final JWTClaimsSetVerifier<C> claimsVerifier);


	/**
	 * Use {@link #getJWTClaimsVerifier()} instead.
	 */
	@Deprecated
	JWTClaimsVerifier getJWTClaimsVerifier();


	/**
	 * Use {@link #setJWTClaimsSetVerifier} instead.
	 */
	@Deprecated
	void setJWTClaimsVerifier(final JWTClaimsVerifier claimsVerifier);
}
