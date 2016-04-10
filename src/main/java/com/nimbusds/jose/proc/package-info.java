/**
 * Secure framework for application-specific verification and decryption of
 * JOSE objects (with arbitrary payloads). Provides a core
 * {@link com.nimbusds.jose.proc.JOSEProcessor interface} for processing JWS,
 * JWE and unsecured (plain) objects, with a
 * {@link com.nimbusds.jose.proc.DefaultJOSEProcessor default implementation}
 * which can be configured and extended as required.
 *
 * <p>To process JSON Web Tokens (JWT) refer to the
 * {@link com.nimbusds.jwt.proc} package.
 */
package com.nimbusds.jose.proc;