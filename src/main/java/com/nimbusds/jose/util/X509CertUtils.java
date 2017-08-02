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

package com.nimbusds.jose.util;


import java.io.ByteArrayInputStream;
import java.security.cert.*;


/**
 *  X.509 certificate utilities.
 *
 *  @author Vladimir Dzhuvinov
 *  @version 2017-08-02
 */
public class X509CertUtils {


	/**
	 * The PEM start marker.
	 */
	private static final String PEM_BEGIN_MARKER = "-----BEGIN CERTIFICATE-----";


	/**
	 * The PEM end marker.
	 */
	private static final String PEM_END_MARKER = "-----END CERTIFICATE-----";


	/**
	 * Parses a DER-encoded X.509 certificate.
	 *
	 * @param derEncodedCert The DER-encoded X.509 certificate, as a byte
	 *                       array. May be {@code null}.
	 *
	 * @return The X.509 certificate, {@code null} if parsing failed.
	 */
	public static X509Certificate parse(final byte[] derEncodedCert) {

		if (derEncodedCert == null || derEncodedCert.length == 0) {
			return null;
		}

		final Certificate cert;
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cert = cf.generateCertificate(new ByteArrayInputStream(derEncodedCert));
		} catch (CertificateException e) {
			return null;
		}

		if (! (cert instanceof X509Certificate)) {
			return null;
		}

		return (X509Certificate)cert;
	}


	/**
	 * Parses a PEM-encoded X.509 certificate.
	 *
	 * @param pemEncodedCert The PEM-encoded X.509 certificate, as a
	 *                       string. May be {@code null}.
	 *
	 * @return The X.509 certificate, {@code null} if parsing failed.
	 */
	public static X509Certificate parse(final String pemEncodedCert) {

		if (pemEncodedCert == null || pemEncodedCert.isEmpty()) {
			return null;
		}

		final int markerStart = pemEncodedCert.indexOf(PEM_BEGIN_MARKER);

		if (markerStart < 0) {
			return null;
		}

		String buf = pemEncodedCert.substring(markerStart + PEM_BEGIN_MARKER.length());

		final int markerEnd = buf.indexOf(PEM_END_MARKER);

		if (markerEnd < 0) {
			return null;
		}

		buf = buf.substring(0, markerEnd);

		buf = buf.replaceAll("\\s", "");

		return parse(new Base64(buf).decode());
	}
	
	
	/**
	 * Returns the specified X.509 certificate as PEM-encoded string.
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return The PEM-encoded X.509 certificate, {@code null} if encoding
	 *         failed.
	 */
	public static String toPEMString(final X509Certificate cert) {
	
		StringBuilder sb = new StringBuilder();
		sb.append(PEM_BEGIN_MARKER);
		sb.append('\n');
		
		try {
			sb.append(Base64.encode(cert.getEncoded()).toString());
		} catch (CertificateEncodingException e) {
			return null;
		}
		sb.append('\n');
		sb.append(PEM_END_MARKER);
		return sb.toString();
	}
	
	
	/**
	 * Computes the X.509 certificate SHA-256 thumbprint ({@code x5t#S256}).
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return The SHA-256 thumbprint, BASE64URL-encoded, {@code null} if
	 *         a certificate encoding exception is encountered.
	 */
	public static Base64URL computeSHA256Thumbprint(final X509Certificate cert) {
	
		try {
			byte[] derEncodedCert = cert.getEncoded();
			return Base64URL.encode(derEncodedCert);
		} catch (CertificateEncodingException e) {
			return null;
		}
	}
}
