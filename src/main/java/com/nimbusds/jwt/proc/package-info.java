/**
 * Secure framework for application-specific processing of JSON Web Tokens
 * (JWTs). Provides a core {@link com.nimbusds.jwt.proc.JWTProcessor interface}
 * for processing signed, encrypted and unsecured (plain) JWTs, with a
 * {@link com.nimbusds.jwt.proc.DefaultJWTProcessor default implementation}
 * which can be configured and extended as required.
 *
 * <p>To process generic JOSE objects refer to the
 * {@link com.nimbusds.jose.proc} package.
 *
 * <p>References:
 *
 * <ul>
 *     <li><a href="http://tools.ietf.org/html/rfc7519">RFC 7519 (JWT)</a>
 * </ul>
 */
package com.nimbusds.jwt.proc;