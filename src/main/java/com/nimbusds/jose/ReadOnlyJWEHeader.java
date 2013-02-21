package com.nimbusds.jose;


import com.nimbusds.jose.util.Base64URL;


/**
 * Read-only view of a {@link JWEHeader JWE header}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-16)
 */
public interface ReadOnlyJWEHeader extends ReadOnlyCommonSEHeader {


	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return The algorithm parameter.
	 */
	@Override
	public JWEAlgorithm getAlgorithm();


	/**
	 * Gets the encryption method ({@code enc}) parameter.
	 *
	 * @return The encryption method parameter.
	 */
	public EncryptionMethod getEncryptionMethod();


	/**
	 * Gets the Ephemeral Public Key ({@code epk}) parameter.
	 *
	 * @return The Ephemeral Public Key parameter, {@code null} if not 
	 *         specified.
	 */
	public ECKey getEphemeralPublicKey();


	/**
	 * Gets the compression algorithm ({@code zip}) parameter.
	 *
	 * @return The compression algorithm parameter, {@code null} if not 
	 *         specified.
	 */
	public CompressionAlgorithm getCompressionAlgorithm();


	/**
	 * Gets the agreement PartyUInfo ({@code apu}) parameter.
	 *
	 * @return The agreement PartyUInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getAgreementPartyUInfo();


	/**
	 * Gets the agreement PartyVInfo ({@code apv}) parameter.
	 *
	 * @return The agreement PartyVInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getAgreementPartyVInfo();


	/**
	 * Gets the encryption PartyUInfo ({@code epu}) parameter.
	 *
	 * @return The encryption PartyUInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getEncryptionPartyUInfo();


	/**
	 * Gets the encryption PartyVInfo ({@code epv}) parameter.
	 *
	 * @return The encryption PartyVInfo parameter, {@code null} if not
	 *         specified.
	 */
	public Base64URL getEncryptionPartyVInfo();
}
