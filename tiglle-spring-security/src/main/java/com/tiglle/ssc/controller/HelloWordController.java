package com.tiglle.ssc.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.CircleCaptcha;
import cn.hutool.core.lang.UUID;
import cn.hutool.core.map.MapBuilder;
import cn.hutool.core.map.MapUtil;
import cn.hutool.json.JSONConfig;
import cn.hutool.json.JSONUtil;
import com.tiglle.ssc.entity.TiglleUserDetails;
import com.tiglle.ssc.service.impl.TiglleUserDetailsServiceImpl;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Map;

@RestController
public class HelloWordController {


    //@Autowired  //测试授权时注掉的，可以放开实现自定义认证
    private AuthenticationProvider authenticationProvider;


    @RequestMapping("hello")
    public String hello() {
        return "hello word";
    }

    //@RequestMapping("index")
    public String index() {
        return "index";
    }

    @RequestMapping("customAuth")
    public String customAuth(String username,String password) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authenticate = authenticationProvider.authenticate(authentication);
        TiglleUserDetails tiglleUserDetails = (TiglleUserDetails)authenticate.getPrincipal();//用户详情
        tiglleUserDetails.getUsername();//username
        tiglleUserDetails.getPassword();//BCryptPasswordEncoder加密后的密码
        Object _password = authenticate.getCredentials();//明文密码
        Collection<? extends GrantedAuthority> authorities = authenticate.getAuthorities();//角色信息
        Object details = authenticate.getDetails();//null
        System.out.println(JSONUtil.toJsonStr(authenticate, JSONConfig.create().setIgnoreNullValue(false).setDateFormat("yyyy-MM-dd HH:mm:ss")));
        return "hello word";
    }

    /**
     * 获取验证码
     * @return
     */
    @RequestMapping("generateCaptcha")
    @ResponseBody
    public Map<String, String> generateCaptcha(){
        //使用hutools生成验证码类，自定义验证码图片长宽
        CircleCaptcha circleCaptcha = CaptchaUtil.createCircleCaptcha(200, 100);
        //生成随机uuid作为此验证码唯一标示
        String uuid = UUID.randomUUID().toString();
        //模拟：验证码存入redis中，过期时间为10分钟，key为uuid，value为circleCaptcha.getCode()
        TiglleUserDetailsServiceImpl.captchaCache.put(uuid, circleCaptcha.getCode());
        //将uuid和验证码图片返回给前端
        Map<String, String> result = MapUtil.builder("id", uuid).map();
        result.put("image", circleCaptcha.getImageBase64());
        return result;
    }


    /**
     * 基于请求url的权限认证测试
     * @return
     */
    @ResponseBody
    @GetMapping("/list1")
    public String testAuthorizationUrl(){
        return "list1";
    }

    @ResponseBody
    @GetMapping("/securityContext")
    public String getSecurityContext(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return JSONUtil.toJsonStr(authentication.getCredentials(),JSONConfig.create().setIgnoreNullValue(false));
    }
}
