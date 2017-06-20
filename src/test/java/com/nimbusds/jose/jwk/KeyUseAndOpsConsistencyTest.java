/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.jwk;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import junit.framework.TestCase;


/**
 * @author Vladimir Dzhuvinov
 * @version 2017-06-30
 */
public class KeyUseAndOpsConsistencyTest extends TestCase {
	
	
	public void testBothNull() {
		
		assertTrue(KeyUseAndOpsConsistency.areConsistent(null, null));
	}
	
	
	public void testUseNull() {
		
		assertTrue(KeyUseAndOpsConsistency.areConsistent(null, Collections.singleton(KeyOperation.SIGN)));
	}
	
	
	public void testOpsNull() {
		
		assertTrue(KeyUseAndOpsConsistency.areConsistent(KeyUse.SIGNATURE, null));
	}
	
	
	public void testConsistentSignatureUse() {
		
		assertTrue(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY))));
	}
	
	
	public void testConsistentEncryptionUse() {
		
		assertTrue(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.ENCRYPTION,
			new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT))));
		assertTrue(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.ENCRYPTION,
			new HashSet<>(Arrays.asList(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))));
		assertTrue(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.ENCRYPTION,
			new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT, KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))));
	}
	
	
	public void testSignatureUseNotConsistent() {
		
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			Collections.singleton(KeyOperation.ENCRYPT)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			Collections.singleton(KeyOperation.DECRYPT)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			Collections.singleton(KeyOperation.WRAP_KEY)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			Collections.singleton(KeyOperation.UNWRAP_KEY)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			Collections.singleton(KeyOperation.DERIVE_KEY)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			Collections.singleton(KeyOperation.DERIVE_BITS)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT))
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			new HashSet<>(Arrays.asList(KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.SIGNATURE,
			new HashSet<>(Arrays.asList(KeyOperation.ENCRYPT, KeyOperation.DECRYPT, KeyOperation.WRAP_KEY, KeyOperation.UNWRAP_KEY))
		));
	}
	
	
	public void testEncryptionUseNotConsistent() {
		
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.ENCRYPTION,
			Collections.singleton(KeyOperation.SIGN)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.ENCRYPTION,
			Collections.singleton(KeyOperation.VERIFY)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.ENCRYPTION,
			Collections.singleton(KeyOperation.DERIVE_KEY)
		));
		assertFalse(KeyUseAndOpsConsistency.areConsistent(
			KeyUse.ENCRYPTION,
			Collections.singleton(KeyOperation.DERIVE_BITS)
		));
	}
}
