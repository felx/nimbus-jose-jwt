package com.nimbusds.jwt.proc;


/**
 * Clock skew aware interface.
 *
 * @see com.nimbusds.jwt.util.DateUtils
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
