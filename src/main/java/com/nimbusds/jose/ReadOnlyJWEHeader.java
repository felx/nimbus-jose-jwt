package com.nimbusds.jose;


import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * Read-only view of a {@link JWEHeader JWE header}.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-20)
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
	 * Gets the PBES2 salt ({@code p2s}) parameter.
	 *
	 * @return The PBES2 salt parameter, {@code null} if not specified.
	 */
	public Base64URL getPBES2Salt();


	/**
	 * Gets the PBES2 count ({@code p2c}) parameter.
	 *
	 * @return The PBES2 count parameter, zero if not specified.
	 */
	public int getPBES2Count();
}
