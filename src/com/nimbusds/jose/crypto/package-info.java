/**
 * Implementations of selected standard Javascript Object Signing and Encryption
 * (JOSE) algorithms.
 *
 * <p>Provides {@link com.nimbusds.jose.sdk.JWSSigner signers} and 
 * {@link com.nimbusds.jose.sdk.JWSVerifier verifiers} for the following JSON
 * Web Signature (JWS) algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.crypto.MACSigner} for HS256, HS384 and 
 *         HS512.
 *     <li>{@link com.nimbusds.jose.crypto.MACVerifier} for HS256, HS384 and
 *         HS512.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ ($version-date$)
 */
package com.nimbusds.jose.crypto;
 
