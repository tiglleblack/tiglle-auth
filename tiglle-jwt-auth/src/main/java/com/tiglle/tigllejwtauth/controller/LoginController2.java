package com.tiglle.tigllejwtauth.controller;


import cn.hutool.core.date.DateUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

@Controller
public class LoginController2 {

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
        Date date = new Date();
        String token = JWT.create()
                .withAudience(userid)
                .withAudience("userid", userid)
                .withAudience("merchantId", merchantId)
                .withIssuedAt(date).withExpiresAt(DateUtil.offsetMinute(date, 5))
                .sign(Algorithm.HMAC256(secretKey));
        return token;
    }

//    public String login2(){
//        JWT.create().withAudience(user.getId()).withIssuedAt(start).withExpiresAt(end)
//                .sign(Algorithm.HMAC256(user.getPassword()));
//    }
//
//
//    // 验证 token
//    JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(user.getPassword())).build();
//                try {
//        jwtVerifier.verify(token);
//<dependency>
//            <groupId>com.auth0</groupId>
//            <artifactId>java-jwt</artifactId>
//            <version>3.18.3</version>
//        </dependency>

    //验证token
    @GetMapping("auth2")
    @ResponseBody
    public String auth(String token) {
        // 验证 token
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(secretKey)).build();
        try {
            jwtVerifier.verify(token);
        } catch (JWTVerificationException e) {
            return "请登录";
        }
        return "认证成功";
    }
}
