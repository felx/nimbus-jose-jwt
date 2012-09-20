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
	 * Required implementation.
	 */
	REQUIRED,


	/**
	 * Recommended implementation.
	 */
	RECOMMENDED,


	/**
	 * Optional implementation.
	 */
	OPTIONAL;
}
