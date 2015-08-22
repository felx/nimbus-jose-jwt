package com.nimbusds.jwt.proc;


import com.nimbusds.jose.proc.SecurityContext;


/**
 * Configurable processor of {@link com.nimbusds.jwt.PlainJWT
 * unsecured} (plain), {@link com.nimbusds.jwt.SignedJWT signed} and
 * {@link com.nimbusds.jwt.EncryptedJWT encrypted} JSON Web Tokens (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-22
 */
public interface ConfigurableJWTProcessor<C extends SecurityContext>
	extends JWTProcessor<C>, JWTProcessorConfiguration<C> {

}
