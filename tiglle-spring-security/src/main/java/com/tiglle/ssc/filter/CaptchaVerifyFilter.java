package com.tiglle.ssc.filter;

import cn.hutool.core.util.StrUtil;
import com.tiglle.ssc.TiglleAuthenticationException;
import com.tiglle.ssc.config_前后分离.TiglleJsonAuthenticationFailureHandler;
import com.tiglle.ssc.service.impl.TiglleUserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.GenericFilterBean;


import java.io.IOException;

public class CaptchaVerifyFilter extends GenericFilterBean {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        //登录请求需要验证验证码
        AntPathRequestMatcher loginMatcher = new AntPathRequestMatcher("/custom/login", "POST");
        if (loginMatcher.matches((HttpServletRequest) request)) {
            try {
                //获取请求参数
                String captcha = request.getParameter("captcha");
                String id = request.getParameter("id");
                if (StrUtil.isEmpty(captcha) || StrUtil.isEmpty(id)) {
                    throw new TiglleAuthenticationException("验证码为空");
                }
                //模拟根据id从redis查找验证码
                String s = TiglleUserDetailsServiceImpl.captchaCache.get(id);
                if (StrUtil.isEmpty(s)) {
                    throw new TiglleAuthenticationException("验证码已经过期");
                }
                //校验验证码是否相等
                if (!s.equalsIgnoreCase(captcha)) {
                    throw new TiglleAuthenticationException("验证码错误");
                }
                //验证成功删除本次验证码，继续后续登录流程
                TiglleUserDetailsServiceImpl.captchaCache.remove(id);
                chain.doFilter(request, response);
            } catch (AuthenticationException e) {
                new TiglleJsonAuthenticationFailureHandler().onAuthenticationFailure((HttpServletRequest) request,(HttpServletResponse) response,e);
            }
        }
        //非登录请求直接往后走
        chain.doFilter(request, response);
    }
}
