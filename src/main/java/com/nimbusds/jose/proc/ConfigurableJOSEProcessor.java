package com.nimbusds.jose.proc;


/**
 * Configurable processor of {@link com.nimbusds.jose.PlainObject unsecured}
 * (plain), {@link com.nimbusds.jose.JWSObject JWS} and
 * {@link com.nimbusds.jose.JWEObject JWE} objects.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-08-22
 */
public interface ConfigurableJOSEProcessor<C extends SecurityContext>
	extends JOSEProcessor<C>, JOSEProcessorConfiguration<C> {

}
