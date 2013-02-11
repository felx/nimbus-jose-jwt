package com.nimbusds.jose.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;


public class RSAEncrypter extends RSAProvider implements JWEEncrypter {

    private SecureRandom r;
    private RSAPublicKey pubKey;


    public RSAEncrypter(RSAPublicKey key) {
        pubKey = key;
        try {
             r = SecureRandom.getInstance("SHA1PRNG");
         } catch(NoSuchAlgorithmException e) {

             throw new ProviderException("Java Security provideer doesn't support SHA1PRNG");
         }
    }

    public JWECryptoParts encrypt(ReadOnlyJWEHeader readOnlyJWEHeader, byte[] bytes)
            throws JOSEException {

        EncryptionMethod method = readOnlyJWEHeader.getEncryptionMethod();
        JWEAlgorithm algorithm = readOnlyJWEHeader.getAlgorithm();
        Base64URL encryptedKey = null;
        Base64URL cipherText = null;


        try {
            int keyLength = keyLengthFromMethod(method);
            SecretKey contentEncryptionKey = genAesKey(keyLength);

            if (algorithm.equals(JWEAlgorithm.RSA1_5)) {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                encryptedKey = Base64URL.encode(cipher.doFinal(contentEncryptionKey.getEncoded()));

            } else if (algorithm.equals(JWEAlgorithm.RSA_OAEP)) {
                try {

                    AsymmetricBlockCipher engine = new RSAEngine();
                    OAEPEncoding cipher = new OAEPEncoding(engine);

                    BigInteger mod = pubKey.getModulus();
                    BigInteger exp = pubKey.getPublicExponent();
                    RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
                    cipher.init(true, keyParams);

                    int inputBlockSize = cipher.getInputBlockSize();
                    int outputBlockSize = cipher.getOutputBlockSize();

                    byte[] keyBytes = contentEncryptionKey.getEncoded();

                    encryptedKey = Base64URL.encode(cipher.processBlock(keyBytes, 0, keyBytes.length));

                } catch (InvalidCipherTextException e) {

                    throw new JOSEException(e.getMessage(), e);
                }

            } else {
                throw new JOSEException("Algorithm must be RSA1_5 or RSA_OAEP");
            }


            if (encryptedKey == null ) {
                throw new JOSEException("Error generating encrypted key");
            }

            JWECryptoParts parts;

            if (method.equals(EncryptionMethod.A128GCM) || method.equals(EncryptionMethod.A256GCM)) {
                Base64URL iv = generateJWEIV();

                if (iv == null)
                    throw new JOSEException("Missing initialization vector \"iv\" header");

                byte[] ivBytes = iv.decode();

                IvParameterSpec ivParamSpec = new IvParameterSpec(ivBytes);
                cipherText = Base64URL.encode(aesgcmEncrypt(ivParamSpec, contentEncryptionKey, bytes));
                parts = new JWECryptoParts(encryptedKey,  Base64URL.encode(ivBytes), cipherText , null);
                return parts;

            }
            else{
                throw new JOSEException("Unsupported encryption method");
            }


        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid Key Exception", e);
        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException("Java Security Provider doesn't support the algorithm specified", e);

        } catch (BadPaddingException e) {
            throw new JOSEException("Bad padding exception", e);
        } catch (NoSuchPaddingException e) {
            throw new JOSEException("No such padding Exception", e);
        } catch (IllegalBlockSizeException e) {
            throw new JOSEException("Illegal Block Size exception", e);
        }
    }


    protected static SecretKey genAesKey(final int bitSize) throws NoSuchAlgorithmException {
        KeyGenerator keygen;
        keygen = KeyGenerator.getInstance("AES");
        keygen.init(bitSize);
        return keygen.generateKey();
    }


    //Generate a unique Initialization Vector for the JWE message
    protected Base64URL generateJWEIV() {
        byte[] bytes = new byte[8];
        r.nextBytes(bytes);
        return Base64URL.encode(bytes);

    }


}