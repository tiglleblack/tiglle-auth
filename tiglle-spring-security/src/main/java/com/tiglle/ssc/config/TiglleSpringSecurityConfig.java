package com.tiglle.ssc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.SecurityFilterChain;

//6.0之前是继承WebSecurityConfigurerAdapter来完成
@Configuration
public class TiglleSpringSecurityConfig {
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests()
                //放行的资源，不用认证直接访问
                .requestMatchers("/test").permitAll()
                .requestMatchers("/test2").permitAll()
                .anyRequest().authenticated();
        //开启表单认证
        FormLoginConfigurer<HttpSecurity> httpSecurityFormLoginConfigurer = httpSecurity.formLogin();
        //指定表单认证的登录页面
        //httpSecurityFormLoginConfigurer.loginPage("/login");
        //开启httpBase认证
        httpSecurity.httpBasic();
        return httpSecurity.build();
    }

}
