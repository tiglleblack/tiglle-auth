package com.tiglle.ssc.config__前后不分离;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

//6.0之前是继承WebSecurityConfigurerAdapter来完成
//前后不分离，html再项目中
//@Configuration
public class TiglleSpringSecurityConfig {
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests()
                //放行的资源/login，不用认证直接访问(否则会无限302：ERR_TOO_MANY_REDIRECTS)，其他必须认证
                .requestMatchers("/login.html").permitAll()
                .anyRequest().authenticated();
        //开启表单认证
        http.formLogin()
                //指定登录页面的html
                .loginPage("/login.html")
                //Spring Security默认对POST  /login的请求进行认证，此处可以修改默认认证路径
                .loginProcessingUrl("/custom/login")
                //如果是访问别的页面跳转到登录页面，那么登录成功后会跳回原来的地址。但如果直接访问登录页login.html然后登录成功，SSC默认会跳转到项目跟路径：http://localhost:8080/
                //这里可以修改直接访问登录页login.html然后登录成功后跳转的地址
                .successForwardUrl("/index") //服务器内部转发，如果发生404，很容易被误解为是登录链接请求的404（因为地址栏没变，还是登录时的地址，实际上是/index）
                .defaultSuccessUrl("/index")//浏览器redirect方式，浏览器进行转发，地址会变，两个都配置优先这个配置
                //自定义失败跳转地址
                .failureForwardUrl("/custom/error")//同上，forWard方式，服务器内部转发
                .failureUrl("/custom/error")//同上，redirect方式，浏览器转发
                //Spring Security默认表单登录的用户名密码为username和password，此处可修改默认名称
                .usernameParameter("user")
                .passwordParameter("pass")
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
    //@Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
