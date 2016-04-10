package com.nimbusds.jwt.proc;


import com.nimbusds.jose.util.DateUtils;


/**
 * Clock skew aware interface.
 *
 * @see DateUtils
 */
public interface ClockSkewAware {
	

	/**
	 * Gets the maximum acceptable clock skew.
	 *
	 * @return The maximum acceptable clock skew, in seconds. Zero if none.
	 */
	int getMaxClockSkew();


	/**
	 * Sets the maximum acceptable clock skew.
	 *
	 * @param maxClockSkewSeconds The maximum acceptable clock skew, in
	 *                            seconds. Zero if none.
	 */
	void setMaxClockSkew(final int maxClockSkewSeconds);
}
