package com.nimbusds.jose.proc;


/**
 * Security context. Provides additional information necessary for processing
 * a JOSE object.
 *
 * <p>Example context information:
 *
 * <ul>
 *     <li>Identifier of the message producer (e.g. OpenID Connect issuer) to
 *         retrieve its public key to verify the JWS signature.
 *     <li>Indicator whether the message was received over a secure channel
 *         (e.g. TLS/SSL) which is essential for processing unsecured (plain)
 *         JOSE objects.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-06-10
 */
public interface SecurityContext {


}
