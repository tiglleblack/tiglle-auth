package com.tiglle.ssc.config_授权管理;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//6.0之前是继承WebSecurityConfigurerAdapter来完成
@Configuration
public class TiglleSpringSecurityConfig {
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests()
                //list1请求，必须拥有admin角色才能访问
                .requestMatchers("/list1").hasRole("admin")
                //放行的资源/login，不用认证直接访问(否则会无限302：ERR_TOO_MANY_REDIRECTS)，其他必须认证
                .anyRequest().authenticated();
        //开启表单认证
        http.formLogin()
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

    @Bean //需要注释掉TiglleUserDetailsServiceImpl
    public UserDetailsService userDetailsService(){
            //生成UserDetails管理器
            InMemoryUserDetailsManager detailsManager = new InMemoryUserDetailsManager();
            //添加权限
            detailsManager.createUser(User.withUsername("username").password("{noop}123456").roles("superadmin").build());
            detailsManager.createUser(User.withUsername("user").password("{noop}123456").roles("admin").build());
            //模拟从数据库获取用户
            return detailsManager;
    }

}
