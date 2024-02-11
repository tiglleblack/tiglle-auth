package com.tiglle.ssc.controller;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.CircleCaptcha;
import cn.hutool.core.lang.UUID;
import cn.hutool.core.map.MapBuilder;
import cn.hutool.core.map.MapUtil;
import com.tiglle.ssc.service.impl.TiglleUserDetailsServiceImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HelloWordController {



    @RequestMapping("hello")
    public String hello() {
        return "hello word";
    }

    //@RequestMapping("index")
    public String index() {
        return "index";
    }

    //生成
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

}
