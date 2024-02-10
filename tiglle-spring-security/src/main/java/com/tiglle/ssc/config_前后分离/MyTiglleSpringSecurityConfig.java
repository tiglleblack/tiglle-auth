package com.tiglle.ssc.config_前后分离;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

//6.0之前是继承WebSecurityConfigurerAdapter来完成
//前后分离，页面前端写，前端发送 PSOT /登录url登录
@Configuration
public class MyTiglleSpringSecurityConfig {
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests()
                .anyRequest().authenticated();
        //开启表单认证
        http.formLogin()
                //Spring Security默认对POST  /login的请求进行认证，此处可以修改默认认证路径
                .loginProcessingUrl("/custom/login")
                //Spring Security默认表单登录的用户名密码为username和password，此处可修改默认名称
                .usernameParameter("user")
                .passwordParameter("pass")
                //自定义前后端分离方式登录成功处理器
                // 模拟前端请求：tiglle-spring-security/src/tiglle-http-client/tiglle.http:2
                .successHandler(new TiglleJsonAuthenticationSuccessHandler())
                //自定义前后端分离方式登录失败处理器（TODO）
                //.failureHandler(new TiglleJsonAuthenticationFailureHandler())
        ;
        //开启httpBase认证
        http.httpBasic();
        http.csrf().disable();
        return http.build();
    }

    /**
     * 指定密码加密器
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
