package com.nimbusds.jose;


import java.net.URI;
import java.net.URL;
import java.util.Set;


/**
 * Matches JOSE objects.
 *
 * <p>Supported criteria:
 *
 * <ul>
 *     <li>Any, one or more JOSE classes (plain, JWS, JWE).
 *     <li>Any, one or more algorithms (alg).
 *     <li>Any, one or more encryption methods (enc).
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-04-15)
 */
public class JOSEMatcher {


	private Set<Class> classes;


	private Set<Algorithm> algs;


	private Set<EncryptionMethod> encs;


	private Set<URL> jkus;


	private Set<String> kids;
}
