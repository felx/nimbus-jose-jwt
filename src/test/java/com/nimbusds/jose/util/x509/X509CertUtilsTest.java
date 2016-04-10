package com.nimbusds.jose.util.x509;


import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.util.x509.X509CertUtils;
import junit.framework.TestCase;


/**
 * Tests the X.509 certificate utilities.
 */
public class X509CertUtilsTest extends TestCase {
	

	private static final String PEM_CERT =
		"-----BEGIN CERTIFICATE-----" +
		"MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV" +
		"BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow" +
		"GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz" +
		"LmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1" +
		"cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTUwNDAxMDYyMjM4WhcN" +
		"MTYwNDAxMDYyMjM4WjA8MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0" +
		"ZWQxFzAVBgNVBAMTDmNvbm5lY3QyaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC" +
		"AQ8AMIIBCgKCAQEAlz+BCaVIkxTPKSmgLLqoEqswUBPHPMu0QVTfk1ixt6s6mvRX" +
		"57IsOf4VE/6eXNBvqpbfc6KxH2bAw3E7mbmIBpwCFKbdbYt1hqMn3D3dSAWgYCVB" +
		"1f7m1IVxl4lmN55xO7dk27ytOLUgTfFJ6Xg/N4rK2CQCiQaPzzObYvUkVbONplEL" +
		"HXBZiu3NxALapEGO89k25D9s85MVk8nYgaBhWBDkW4lDJ4m3Tg5GXgXTHQVM+yED" +
		"pWDX0QWFy+8jIG7HEKZOPNMQ5tVMDTaeVPUJHk3N0fiQDAGyg10J4XMaDT9auWcb" +
		"GCAao2SPg5Ya82K0tjT4f+sC8nLBXRMMhPE54wIDAQABo4IBtTCCAbEwDAYDVR0T" +
		"AQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/" +
		"BAQDAgWgMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20v" +
		"Z2RpZzJzMS04Ny5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsG" +
		"AQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRv" +
		"cnkvMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29k" +
		"YWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFk" +
		"ZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSD" +
		"MKIz1/tss/C0LIDOMC0GA1UdEQQmMCSCDmNvbm5lY3QyaWQuY29tghJ3d3cuY29u" +
		"bmVjdDJpZC5jb20wHQYDVR0OBBYEFMyPo6ETFAUYEOtCPxvAH0CTJq4mMA0GCSqG" +
		"SIb3DQEBCwUAA4IBAQCWAgw3I4dLkLe/GLrFCtSlcHg/pVZiHEFoTHry6J/GVWln" +
		"2CqxZa9vCtKVWzzeRjRg7Nfa/qhnsnJZ+TqsHH5qVDAPUTEufvNAZBV3vzd8kx4M" +
		"l+zfgP+mCqagE/S0DMhMrIl6Tx6/s1uQkVdApjBa073FCnJq/rUlCUJfWTvP4xgN" +
		"KcztsToQDczLHLr7v8w1JQoHqrKC6K2Tj297nKs097rVFbW/3mHkWLTu30djGJIP" +
		"63oxR9Nw7JVZRrH/8On4h4DVwJC5jl+Le1aJm4RgqtVopDukK5ga5kPwteV6erNZ" +
		"X9x/niTIBH0P3DOlO7s4eFIIAfuI0JAUF3CmUxBy" +
		"-----END CERTIFICATE-----";


	private static final String PEM_CERT_WITH_WHITESPACE =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV\n" +
		"BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow\n" +
		"GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz\n" +
		"LmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1\n" +
		"cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTUwNDAxMDYyMjM4WhcN\n" +
		"MTYwNDAxMDYyMjM4WjA8MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0\n" +
		"ZWQxFzAVBgNVBAMTDmNvbm5lY3QyaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
		"AQ8AMIIBCgKCAQEAlz+BCaVIkxTPKSmgLLqoEqswUBPHPMu0QVTfk1ixt6s6mvRX\n" +
		"57IsOf4VE/6eXNBvqpbfc6KxH2bAw3E7mbmIBpwCFKbdbYt1hqMn3D3dSAWgYCVB\n" +
		"1f7m1IVxl4lmN55xO7dk27ytOLUgTfFJ6Xg/N4rK2CQCiQaPzzObYvUkVbONplEL\n" +
		"HXBZiu3NxALapEGO89k25D9s85MVk8nYgaBhWBDkW4lDJ4m3Tg5GXgXTHQVM+yED\n" +
		"pWDX0QWFy+8jIG7HEKZOPNMQ5tVMDTaeVPUJHk3N0fiQDAGyg10J4XMaDT9auWcb\n" +
		"GCAao2SPg5Ya82K0tjT4f+sC8nLBXRMMhPE54wIDAQABo4IBtTCCAbEwDAYDVR0T\n" +
		"AQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/\n" +
		"BAQDAgWgMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20v\n" +
		"Z2RpZzJzMS04Ny5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsG\n" +
		"AQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRv\n" +
		"cnkvMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29k\n" +
		"YWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFk\n" +
		"ZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSD\n" +
		"MKIz1/tss/C0LIDOMC0GA1UdEQQmMCSCDmNvbm5lY3QyaWQuY29tghJ3d3cuY29u\n" +
		"bmVjdDJpZC5jb20wHQYDVR0OBBYEFMyPo6ETFAUYEOtCPxvAH0CTJq4mMA0GCSqG\n" +
		"SIb3DQEBCwUAA4IBAQCWAgw3I4dLkLe/GLrFCtSlcHg/pVZiHEFoTHry6J/GVWln\n" +
		"2CqxZa9vCtKVWzzeRjRg7Nfa/qhnsnJZ+TqsHH5qVDAPUTEufvNAZBV3vzd8kx4M\n" +
		"l+zfgP+mCqagE/S0DMhMrIl6Tx6/s1uQkVdApjBa073FCnJq/rUlCUJfWTvP4xgN\n" +
		"KcztsToQDczLHLr7v8w1JQoHqrKC6K2Tj297nKs097rVFbW/3mHkWLTu30djGJIP\n" +
		"63oxR9Nw7JVZRrH/8On4h4DVwJC5jl+Le1aJm4RgqtVopDukK5ga5kPwteV6erNZ\n" +
		"X9x/niTIBH0P3DOlO7s4eFIIAfuI0JAUF3CmUxBy\n" +
		"-----END CERTIFICATE-----\n";


	public void testParsePEM()
		throws Exception {

		X509Certificate cert = X509CertUtils.parse(PEM_CERT);

		assertEquals("X.509", cert.getType());
		assertEquals("CN=connect2id.com,OU=Domain Control Validated", cert.getSubjectX500Principal().getName());
		assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
	}

	public void testParsePEM_withWhitespace()
		throws Exception {

		X509Certificate cert = X509CertUtils.parse(PEM_CERT_WITH_WHITESPACE);

		assertEquals("X.509", cert.getType());
		assertEquals("CN=connect2id.com,OU=Domain Control Validated", cert.getSubjectX500Principal().getName());
		assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
	}
}
