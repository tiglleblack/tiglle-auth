package com.tiglle.tigllejwtauth.controller_非对称加密;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

public class KeyGeneratorMain {

    public static void main(String[] args) throws Exception {
        //生成密钥的密文
        String secret = "aabcdefg123456";

        //如果JTWT是SignatureAlgorithm.HS512 加解密，公私钥的长度需要大于等于2048
        Integer keySize = 2048;
        String projectDir = System.getProperty("user.dir");
        String srcDir = projectDir+"/tiglle-jwt-auth/src/main/resources";
        String publicKeyFilePath = srcDir+"/rsa.pub";
        String privateKeyFilePath = srcDir+"/rsa.pri";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom(secret.getBytes());
        keyPairGenerator.initialize(keySize, secureRandom);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        // 获取公钥并写出
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        publicKeyBytes = Base64.getEncoder().encode(publicKeyBytes);
        writeFile(publicKeyFilePath, publicKeyBytes);

        // 获取私钥并写出
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        privateKeyBytes = Base64.getEncoder().encode(privateKeyBytes);
        writeFile(privateKeyFilePath, privateKeyBytes);
    }

    private static void writeFile(String destPath, byte[] bytes)throws Exception{
        File file = new File(destPath);
        File parentFile = file.getParentFile();
        if (!parentFile.exists()) {
            parentFile.mkdirs();
        }
        if (!file.exists()) {
            file.createNewFile();
        }
        Files.write(file.toPath(), bytes);
    }
}
