package com.nimbusds.jose.crypto;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Utility for creating AlgorithmParameters objects with an optional provider
 * @author Justin Richer
 *
 */
class AlgorithmParametersHelper {

	
	public static AlgorithmParameters getInstance(String name, Provider provider) throws NoSuchAlgorithmException {
		if (provider == null) {
			return AlgorithmParameters.getInstance(name);
		} else {
			return AlgorithmParameters.getInstance(name, provider);
		}
	}
	
}
