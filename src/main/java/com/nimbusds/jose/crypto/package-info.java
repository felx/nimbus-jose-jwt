/**
 * Implementations of selected Javascript Object Signing and Encryption (JOSE)
 * algorithms.
 *
 * <p>Provides {@link com.nimbusds.jose.JWSSigner signers} and 
 * {@link com.nimbusds.jose.JWSVerifier verifiers} for the following JSON Web
 * Signature (JWS) algorithms:
 *
 * <ul>
 *     <li>For HMAC algorithms HS256, HS384 and HS512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.MACSigner}
 *             <li>{@link com.nimbusds.jose.crypto.MACVerifier}
 *         </ul>
 *     <li>For RSA-SSA signatures RS256, RS384, RS512, PS256, PS384 and PS512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.RSASSASigner}
 *             <li>{@link com.nimbusds.jose.crypto.RSASSAVerifier}
 *         </ul>
 *      <li>For ECDSA signatures ES256, ES384 and ES512:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.ECDSASigner}
 *             <li>{@link com.nimbusds.jose.crypto.ECDSAVerifier}
 *         </ul>
 * </ul>
 *
 * <p>Provides {@link com.nimbusds.jose.JWEEncrypter encrypters} and 
 * {@link com.nimbusds.jose.JWEDecrypter decrypters} for the following JSON
 * Web Encryption (JWE) algorithms:
 *
 * <ul>
 *     <li>For RSAES-PKCS1-V1_5 and RSA OAEP with A128CBC-HS256, A192CBC-HS384,
 *         A256CBC-HS512, A128GCM, A192GCM and A256GCM encryption:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.RSAEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.RSADecrypter}
 *         </ul>
 *     <li>For AES GCM with A128CBC-HS256, A192CBC-HS384,
 *         A256CBC-HS512, A128GCM, A192GCM and A256GCM encryption:
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.AESEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.AESDecrypter}
 *         </ul>
 *     <li>For direct A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM,
 *         A192GCM and A256GCM encryption (using a shared symmetric key):
 *         <ul>
 *             <li>{@link com.nimbusds.jose.crypto.DirectEncrypter}
 *             <li>{@link com.nimbusds.jose.crypto.DirectDecrypter}
 *         </ul>
 * </ul>
 */
package com.nimbusds.jose.crypto;
