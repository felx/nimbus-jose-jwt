package com.nimbusds.jose.jca;


import java.security.Provider;
import java.security.Security;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import junit.framework.TestCase;


public class DumpSupportedJCAAlgs extends TestCase {
	

	public void testDumpAlgs() {

		for (Provider provider: Security.getProviders()) {
			System.out.println(provider.getName());
			for (String key: provider.stringPropertyNames())
				System.out.println("\t" + key + "\t" + provider.getProperty(key));
		}
	}

	public void testDumpBC() {

		Provider provider = BouncyCastleProviderSingleton.getInstance();

		for (String key: provider.stringPropertyNames())
		System.out.println("\t" + key + "\t" + provider.getProperty(key));
	}
}
