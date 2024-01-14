package com.tiglle.tigllejwtauth.controller_对称加密;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Calendar;
import java.util.HashMap;

//com.auth0.java-jwt  依赖类型的jwt
@Controller
public class LoginController2_java_jwt {

    @Value("${tiglle.username:xiaoming}")
    private String username;

    @Value("${tiglle.password:xiaoming}")
    private String password;

    @Value("${tiglle.secretKey:qwertyyu.qwertyu}")
    private String secretKey;

    @GetMapping("login2")
    @ResponseBody
    public String login(String username, String password) {
        if (!username.equals(username) || !password.equals(password)) {
            return "账号或者密码错误";
        }
        String userid = "123456";
        String merchantId = "QC";
        // 过期时间，60s
        Calendar expires = Calendar.getInstance();
        expires.add(Calendar.SECOND, 600);
        HashMap<String, Object> headers = new HashMap();
        String jwtToken = JWT.create()
                // 第一部分Header
                .withHeader(headers)
                // 第二部分Payload
                .withClaim("userId", 20)
                .withClaim("userName", "LJJ")
                .withExpiresAt(expires.getTime())
                // 第三部分Signature
                .sign(Algorithm.HMAC256(secretKey));
        return jwtToken;
    }

    //验证token
    @GetMapping("auth2")
    @ResponseBody
    public String auth(String token) {
        // 验证 token
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(secretKey)).build();
        try {
            jwtVerifier.verify(token);//只验证，不获取数据，可以只用这个
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            Integer userId = decodedJWT.getClaim("userId").asInt();
            String userName = decodedJWT.getClaim("userName").asString();
            System.out.println(userId+":"+userName);
        } catch (JWTVerificationException e) {
            return "请登录";
        }
        return "认证成功";
    }
}
