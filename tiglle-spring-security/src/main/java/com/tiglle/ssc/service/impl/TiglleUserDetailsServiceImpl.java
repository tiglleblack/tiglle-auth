package com.tiglle.ssc.service.impl;

import com.tiglle.ssc.entity.TiglleUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class TiglleUserDetailsServiceImpl implements UserDetailsService {

    //模拟redis缓存，存放验证码，实际上这个需要使用redis
    public static Map<String, String> captchaCache = new HashMap<String, String>();

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //模拟从数据库获取用户
        TiglleUserDetails tiglleUserDetails = userMappergetUserByName(username);
        return tiglleUserDetails;
    }

    private TiglleUserDetails userMappergetUserByName(String username) {
        TiglleUserDetails tiglleUserDetails = new TiglleUserDetails();
        tiglleUserDetails.setUsername(username);
        //此处设置了密码加密器：com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig.passwordEncoder
        //所以模拟密码已经加密放入了数据库
        tiglleUserDetails.setPassword(new BCryptPasswordEncoder().encode("xiaoming"));
        tiglleUserDetails.setPhone("2345643");
        tiglleUserDetails.setAccountNonExpired(true);//没过期
        tiglleUserDetails.setAccountNonLocked(true);//没锁定
        tiglleUserDetails.setCredentialsNonExpired(true);//票据没过期
        tiglleUserDetails.setEnabled(true);
        return tiglleUserDetails;
    }
}
