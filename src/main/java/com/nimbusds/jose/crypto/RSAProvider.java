package com.nimbusds.jose.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEAlgorithmProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.HashSet;
import java.util.Set;



public class RSAProvider implements JWEAlgorithmProvider {

    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;

    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;


    static {
        Set<JWEAlgorithm> algs = new HashSet<JWEAlgorithm>();
        algs.add(JWEAlgorithm.RSA_OAEP);
        algs.add(JWEAlgorithm.RSA1_5);
        SUPPORTED_ALGORITHMS = algs;

        Set<EncryptionMethod> methods = new HashSet<EncryptionMethod>();
        methods.add(EncryptionMethod.A256GCM);
        methods.add(EncryptionMethod.A128GCM);
        SUPPORTED_ENCRYPTION_METHODS = methods;
    }


    public Set<JWEAlgorithm> supportedAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }

    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return SUPPORTED_ENCRYPTION_METHODS;
    }

    protected int keyLengthFromMethod(EncryptionMethod method) {
        if (method.equals(EncryptionMethod.A128CBC_HS256) ||
                method.equals(EncryptionMethod.A128GCM)) {
            return 128;
        } else if (method.equals(EncryptionMethod.A256GCM) ||
                method.equals(EncryptionMethod.A256CBC_HS512)) {
            return 256;
        } else {
            throw new RuntimeException("Unsupported algorithm, must be RSA1_5 or RSA_OAEP");
        }
    }


    protected byte[] aesgcmDecrypt(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] cipherText)
            throws JOSEException {
        return aesgcm(ivParamSpec, secretKey, cipherText, Cipher.DECRYPT_MODE);
    }

    protected byte[] aesgcmEncrypt(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] cipherText)
            throws JOSEException {
        return aesgcm(ivParamSpec, secretKey, cipherText, Cipher.ENCRYPT_MODE);
    }

    private byte[] aesgcm(IvParameterSpec ivParamSpec, SecretKey secretKey, byte[] cipherText, int encryptMode) throws JOSEException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
            cipher.init(encryptMode, secretKey, ivParamSpec);
            return cipher.doFinal(cipherText);

        } catch (Exception e) {

            throw new JOSEException(e.getMessage());
        }

    }

}
