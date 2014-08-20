package com.nimbusds.jose;


/**
 * Enumeration of JOSE algorithm implementation requirements. Refers to the 
 * requirement levels defined in RFC 2119.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-17)
 */
public enum Requirement {


	/**
	 * The implementation of the algorithm is required.
	 */
	REQUIRED,


	/**
	 * The implementation of the algorithm is recommended.
	 */
	RECOMMENDED,


	/**
	 * The implementation of the algorithm is optional.
	 */
	OPTIONAL
}
