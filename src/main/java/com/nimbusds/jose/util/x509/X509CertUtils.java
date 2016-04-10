package com.nimbusds.jose.util.x509;


import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.nimbusds.jose.util.base64.Base64;


/**
 *  X.509 certificate utilities.
 *
 *  @author Vladimir Dzhuvinov
 *  @version 2015-11-16
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
}
