package com.nimbusds.jose;


import java.util.Set;

import com.nimbusds.jose.jca.JCAAware;
import com.nimbusds.jose.jca.JWEJCAContext;


/**
 * JSON Web Encryption (JWE) provider.
 *
 * <p>The JWE provider can be queried to determine its algorithm capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version 2015-05-26
 */
public interface JWEProvider extends JOSEProvider, JCAAware<JWEJCAContext> {


	/**
	 * Returns the names of the supported algorithms by the JWE provider
	 * instance. These correspond to the {@code alg} JWE header parameter.
	 *
	 * @return The supported JWE algorithms, empty set if none.
	 */
	Set<JWEAlgorithm> supportedJWEAlgorithms();


	/**
	 * Returns the names of the supported encryption methods by the JWE
	 * provier. These correspond to the {@code enc} JWE header parameter.
	 *
	 * @return The supported encryption methods, empty set if none.
	 */
	Set<EncryptionMethod> supportedEncryptionMethods();
}
