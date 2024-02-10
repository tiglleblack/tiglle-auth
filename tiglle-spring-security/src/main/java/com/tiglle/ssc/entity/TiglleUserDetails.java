package com.tiglle.ssc.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TiglleUserDetails implements UserDetails {
    //继承自UserDetails的，名字必须相同，不能修改(即使使用 http.formLogin().setUserParameter()设置了不同的值，这里也不能修改(两处可以不一样，不影响))
    private String username;
    private String password;
    private Set<GrantedAuthority> authorities;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;
    //自定义的
    private String phone;
    private String sex;

}
