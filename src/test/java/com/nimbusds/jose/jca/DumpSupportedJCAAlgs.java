/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

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
