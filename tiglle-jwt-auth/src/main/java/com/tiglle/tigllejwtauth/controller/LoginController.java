package com.tiglle.tigllejwtauth.controller;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * io.jsonwebtoken.jjwt 依赖类型的jwt
 */
@Controller
public class LoginController {

    @Value("${tiglle.username:xiaoming}")
    private String username;

    @Value("${tiglle.password:xiaoming}")
    private String password;

    @Value("${tiglle.secretKey:qwertyyu.qwertyu}")
    private String secretKey;

    @GetMapping("login1")
    @ResponseBody
    public String login(String username,String password){
        if (!username.equals(username) || !password.equals(password)) {
            return "账号或者密码错误";
        }
        //生存JWT token
        // JWT头部分信息【Header】
        Map<String, Object> header = new HashMap();
        header.put("alg", "HS256");
        header.put("typ", "JWT");
        // 载核【Payload】
        Map<String, Object> payload = new HashMap();
        payload.put("userid", "1234567890");
        payload.put("username","xiaoming");
        payload.put("merchantId","QC");
        //token过期时间
        DateTime expiredTime = DateUtil.offsetMinute(new Date(), 5);
        //生存token
        // 生成Token (对称加密)
        String token = Jwts.builder()
                .setHeader(header)// 设置Header
                .setClaims(payload) // 设置载核
                .setExpiration(expiredTime)// 设置生效时间
                .signWith(SignatureAlgorithm.HS256,secretKey) // 签名,这里采用私钥进行签名,不要泄露了自己的私钥信息
                .compact(); // 压缩生成xxx.xxx.xxx
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
    @GetMapping("auth1")
    @ResponseBody
    public String auth(String token){
        // 解析token
        try {
            Jws<Claims> claimsJws = Jwts
                    .parser()
                    .setSigningKey(secretKey)
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
