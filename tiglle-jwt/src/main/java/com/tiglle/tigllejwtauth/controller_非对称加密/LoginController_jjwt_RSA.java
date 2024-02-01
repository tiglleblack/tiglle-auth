package com.tiglle.tigllejwtauth.controller_非对称加密;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * io.jsonwebtoken.jjwt 依赖类型的jwt
 */
@Controller
public class LoginController_jjwt_RSA {

    @Value("${tiglle.username:xiaoming}")
    private String username;

    @Value("${tiglle.password:xiaoming}")
    private String password;

    //从文件中复制过来，生成方式见:com.tiglle.tigllejwtauth.controller_非对称加密.KeyGeneratorMain  或者用代码从文件中读取
    @Value("${tiglle.privateKey:" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDNGpQOfsYFxsnelKJLyzWJz1DOuuH1ksGYpsabepUPee2+/QovSocuZe+dL7YwsoBxY0UWNBhZjJqbbjzOyzk22OiiLr5sftSnLnRZDI4ADliAW0d0SNsHDuqDqu0BNWUCpQWrXhu9IXr7Z6MuD2NRNYc7f1SuVr6J/P17ydY6jFb8pMp0ruIOR386xW1y1u3mMib0AWFa+Vd1wvdbo7nQT50h9k9r+kaXmUY0vgLYqQv4mV5NK/5Ws1vqw5/55VgXP1qTST8fcznExXWc4mTDg85S7wJ0mIkqeLQi3oil+mTqE6Mq0xPgiZcy9ten0dRgq0+GFA73PovrgU/azWXzAgMBAAECggEBAMjU+Zyn7ebCG/DiwXhN5oKmiY2j2JXJud9rjpW3ljWtQmr9AvgDlhKMpe/YRCGy56ofdgqjwCQPVWRUsR4cSE24XzJPaw55smhxSGPZs0HCyk4FExZ+MFnc9S0wNRo12k6Yn9CJOcgb/HwnotT7JFjkfSJ5L8X2EmSzYNHRdP+loYqx9oRqtKAWzWkd7byfhS4eDWYg8DIRMkxj0ODxNYlfJEkDEbqI8gG6HsQ4l193V0wYi7bcgTYauBwSdC0p/DiD4x3zpZYGPePL8nWJT6ZOeKOiWNF46QEB7Tqt6fHbWFJ9/iVoHM9QOBIPKmvVK+AQc9tAqYBmMWJt6Eh0DOECgYEA90b4nTHEr35IXfj2Wfcixu9CyZZdFfverWkmcrixVofdje0S8M6RXG9c1nwQvSReBgNbA5UqXMnQ+dnycBUz5/rQS5yGK4uYjFFh0+ApGNNdj9shoNnMWdDjevNYSxKUlJCsR0M8HgBWgm+FZxZY/CPO8fHChjzgnKNByb7TR98CgYEA1FbC+YTYQe8acUhGL0EewSbTTE6RpbFXcYXYWivuKk5IfAiT7JQ1NiJhGpjH+Fwil8a+wxSnCs8bSxOJG5jvohxWcCa//6P0o95LZl7txlzTKNZyreFijhBP5ZFkjXU/5Bzeghu+ls46S9KGkKVjXhjYIyEvkwg0+0uiRYmRtG0CgYBTPAR7hUEbgXqCh0cFSXbfV7I3gPGccMenv3k9rIWlBt7A40g43o93edTaLbDEufUcOQzty8wSp6w8Ley5ZamvMHHkwa84ASk8MjinxRCQVrVrsutC5Y0vvmyT+k2CF6MDzx7ubedSgfKcvUU+SftyA+uo7SP5Y4yHrTx72EvuKQKBgQCU9IA2NeDW7/qmuUKy54XBjZDwmLVHfM6QzonlR6f9eYkTqZjLf3SMkzV3SPIO4eNKgZtUkmpUBNFqqzulZnXETQi+CBDsLoHxaoGOQM2gN4HRxg4QuGlAq2TA8GuPaE73oODeeMQMWoM+qWLImZzJZ7hHfII5LKquFnKxQT47SQKBgDT0xjFp285q9asZoHSMeG5eOTRwrMaCJrGRs5sDhsjsTanOH52erGJtIT0gUsyZ7PR9/UBQV38FomlozKyBBiIhW6Ms5ztXDaxVcfg0T0x+EQnB9xXEhd7skvIG+j7Crs4MzzIVWq4ly7Zm/5/RZUA412Nj7k5jib3nTwalYqVs" +
            "}")
    private String privateKeyStr;
    @Value("${tiglle.publicKey:" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzRqUDn7GBcbJ3pSiS8s1ic9Qzrrh9ZLBmKbGm3qVD3ntvv0KL0qHLmXvnS+2MLKAcWNFFjQYWYyam248zss5Ntjooi6+bH7Upy50WQyOAA5YgFtHdEjbBw7qg6rtATVlAqUFq14bvSF6+2ejLg9jUTWHO39Urla+ifz9e8nWOoxW/KTKdK7iDkd/OsVtctbt5jIm9AFhWvlXdcL3W6O50E+dIfZPa/pGl5lGNL4C2KkL+JleTSv+VrNb6sOf+eVYFz9ak0k/H3M5xMV1nOJkw4POUu8CdJiJKni0It6Ipfpk6hOjKtMT4ImXMvbXp9HUYKtPhhQO9z6L64FP2s1l8wIDAQAB" +
            "}")
    private String publicKeyStr;


    private static String projectDir = System.getProperty("user.dir");
    private static String srcDir = projectDir+"/tiglle-jwt-auth/src/main/resources";
    private static String publicKeyFilePath = srcDir+"/rsa.pub";
    private static String privateKeyFilePath = srcDir+"/rsa.pri";

    private byte[] getKeyFromFile(String filePath)throws Exception{
        File file = new File(filePath);
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] bytes = new byte[fileInputStream.available()];
        // 读取文件内容到字节数组
        fileInputStream.read(bytes);
        return Base64.getDecoder().decode(bytes);
    }



    @GetMapping("login3")
    @ResponseBody
    public String login(String username,String password) throws Exception {
        if (!username.equals(username) || !password.equals(password)) {
            return "账号或者密码错误";
        }
        //生存JWT token
        // JWT头部分信息【Header】
        Map<String, Object> header = new HashMap();
        header.put("alg", "RS256");//这里应该跟下面的算法保持一致(应该是这样，之前是HS256)
        header.put("typ", "JWT");
        // 载核【Payload】
        Map<String, Object> payload = new HashMap();
        payload.put("userid", "1234567890");
        payload.put("username","xiaoming");
        payload.put("merchantId","QC");
        //token过期时间
        DateTime expiredTime = DateUtil.offsetMinute(new Date(), 5);
        //获取私钥对象
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr.getBytes(StandardCharsets.UTF_8)));//从配置中获取
        //PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(getKeyFromFile(privateKeyFilePath));//从文件中获取
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //生存token
        // 生成Token (对称加密)
        String token = Jwts.builder()
                .setHeader(header)// 设置Header
                .setClaims(payload) // 设置载核
                .setExpiration(expiredTime)// 设置过期时间
                .setIssuedAt(new Date())//设置签发时间(token生成的时间)
                //使用私钥加密
                .signWith(SignatureAlgorithm.RS256, privateKey) // 签名,这里采用私钥进行签名,不要泄露了自己的私钥信息
                .setId(UUID.randomUUID().toString())//是JWT的唯一标识，根据业务需要，这个可以设置为一个不重复的值，主要用来作为一次性token,从而回避重放攻击
                .compact(); // 压缩生成xxx.xxx.xxx
        return token;
    }

    //验证token
    @GetMapping("auth3")
    @ResponseBody
    public String auth(String token){
        // 解析token
        try {
            //获取公钥对象
            //X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(privateKeyStr.getBytes(StandardCharsets.UTF_8)));//从配置中获取
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(getKeyFromFile(publicKeyFilePath));//从文件中获取
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Jws<Claims> claimsJws = Jwts
                    .parser()
                    //使用公钥解密
                    .setSigningKey(publicKey)
                    .parseClaimsJws(token);
            //获取Header信息
            JwsHeader header = claimsJws.getHeader();
            System.out.println(header);
            //获取Payload
            Claims body = claimsJws.getBody();
            System.out.println(body);
            //获取Signature
            String signature = claimsJws.getSignature();
            System.out.println(signature);
            //验证：用户名相等并且token未过期
            String username = body.get("username").toString();
            Date expiration = body.getExpiration();
            if (username.equals(this.username) && DateUtil.compare(expiration, DateUtil.date()) != 0) {
                //查询用户并验证密码，如果是对的
                return "访问成功";
            }
        } catch (Exception e) {
            return "没有权限，请登录";
        }
        return "没有权限，请登录";
    }

}
