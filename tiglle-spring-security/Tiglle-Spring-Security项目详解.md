# 这里只讲大概流程，具体请看SpringSecurity源码解析.md

#### 一：初始项目

​    不添加spring-boot-starter-security的时候，访问控制器：http://localhost:8080/hello，可以随便访问

#### 二：添加SpringSecurity依赖

######     1.添加spring-boot-starter-security之后，什么都不做，启动的时候，控制台提示：

```shell
Using generated security password: 3ae5a6fb-c108-403c-ace2-63273408c5b3

This generated password is for development use only. Your security configuration must be updated before running your application in production.
```

###### 2.再次访问控制器：http://localhost:8080/hello，出现登录页面，使用账密：user,1029d33d-f87f-412d-bb4f-0da8ebaca8a8登录后成功访问

###### 3.自定义登录验证

1.先配置认证器：向Spring注入DaoAuthenticationProvider(UsernamePasswordAuthenticationToken专用)

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig#authenticationManager

2.使用DaoAuthenticationProvider进行认证

com.tiglle.ssc.controller.HelloWordController#customAuth 

#### 三.自定义配置

https://yunyanchengyu.blog.csdn.net/article/details/129824895

##### 1.自定义登录页面

编写登录页面：src/main/resources/static/login.html

##### 2.自定义各种配置：前后不分离

登录成功后跳转指定的url或者页面

com.tiglle.ssc.config__前后不分离.TiglleSpringSecurityConfig

##### 3.自定义各种配置：前后分离

登录成功后返回JSON数据

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig

#### 四.注销登录

https://yunyanchengyu.blog.csdn.net/article/details/129833839

#### 五.会话管理

https://yunyanchengyu.blog.csdn.net/article/details/129792030

###### 1.可以修改session的生成策略

###### 2.可以设置session的过期时间

###### 3.可以设置session失效后的跳转url

###### 4.默认浏览器关闭清除标识session的JSESSIONID的cookie，可以设置logout后删除JSESSIONID的cookie

###### 5.多用户登录控制

默认SSC允许多个用户再不同的地方登录，可以设置最大会话数，来限制同时登录用户数量。

可以设置后登录的用户无法登录 或者 后登录的挤出先登录的用户

###### 6.会话攻击保护

1、攻击者Attacker以一个合法的用户身份登录www.website.com。

2、服务器与攻击者Attacker建立了一个会话，sessionid为1234567（这里只是一个示例，大家不要在乎sessionid的位数对不对）。应用网站服务器返回一个会话ID给他；

3、攻击者Attacker用该会话ID构造了一个URL：http://www.website.com/login.jsp?sessionid=1234567，发给了受害者Alice ；

4- 受害者Victim点击该链接,进行了登录;

5、受害者Victim输入她的合法用户名和密码，正常登录了该网站，会话成功建立（注意，由于此时的sessionid预先已经被Bob设置为1234567了）；

6、攻击者Attacker用该会话ID成功冒充并劫持了受害者Victim的会话，这时攻击者Attacker如果输入http://www.website.com/viewprofile.jsp?sessionid=1234567，就可以看到受害者Victim的个人信息（profile）了，因此sessionid此时就是代表了Victim；

###### 7.前后分离时会话失效返回JSON数据设置

###### 8.登录信息保存的方式

1.保存到session中

2.保存到requset中

3.获取登录信息的方式

https://blog.csdn.net/cloume/article/details/84983006

#### 六.会话管理

https://yunyanchengyu.blog.csdn.net/article/details/130175273

###### 1.SecurityContext介绍

存储登录之后用户信息的容器

###### 2.SecurityContextHolder

用户登录后用户信息的持有者，可通过这个类获取，默认从当前线程的ThreadLocal中获取

因为登录成功后，用户信息会被放入：

1.Session中，key=SPRING_SECURITY_CONTEXT

2.ThreadLocal中

3.Request中，key=org.springframework.security.web.context.RequestAttributeSecurityContextRepository.SPRING_SECURITY_CONTEXT

所以可以从这三个地方获取

###### 3.SecurityContextHolderStrategy

决定了SecurityContextHolder获取SecurityContext的策略

有4个实现类，默认使用ThreadLocalSecurityContextHolderStrategy：从ThreadLocal中获取

#### 六.验证码功能

https://yunyanchengyu.blog.csdn.net/article/details/129990525

###### 1.使用hutools生成验证码，存入redis，每次返回代表此验证码的唯一id和base64的验证码图片数据给前端

com.tiglle.ssc.controller.HelloWordController#generateCaptcha

###### 2.放行验证码生成的链接

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig#defaultSecurityFilterChain

###### 3.创建验证码检验过滤器

com.tiglle.ssc.filter.CaptchaVerifyFilter

###### 4.配置验证码校验过滤器到SSC中

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig

#### 七.短信验证码登录功能

https://yunyanchengyu.blog.csdn.net/article/details/119782672

###### 1.发送验证码和防刷功能

1.用户获取验证码时，以phone number为key，从redis中获取值：验证码_时间戳

2.如果没获取到，表示第一次获取，生成验证码并存入redis，值为 验证码_当前系统时间戳，key为phone number,并发送短信给用户

3.如果获取到了，用当前时间戳-获取到的时间戳，如果小于60S，提示一分钟后再试

###### 2.自定义验证码认证票据

1.参考UsernamePasswordAuthenticationToken自定义SmsAuthenticationToken

2.自定义过滤器SmsAuthenticationFilter，拦截验证码登录url：/sms/login

3.自定义UserDetailsService，验证用户输入的验证码和redis中的验证码是否相等，以及根据手机号查询用户信息

4.模拟AuthenticationProvider(

Spring默认对UsernamePassowrdAuthenticationToken类型的票据进行认证

)，自定义SmsAuthenticationProvider，对自定义SmsAuthenticationToken进行认证

5.自定义配置类，将自定义过滤器和自定义认证提供者

6.设置配置类到SSC的配置类中

#### 八.密码生成和校验器

https://yunyanchengyu.blog.csdn.net/article/details/129843394

###### 1.各种密码校验器介绍

###### 2.怎么选择使用哪种校验器

###### 3.Spring默认的密码校验器

根据存储密码的{加密方式}前缀，决定使用哪个校验器

例子：

| username | password_bcrypt    | password_argon2    |
| -------- | ------------------ | ------------------ |
| xiaoming | {bcrypt}加密后密文 | {argon2}加密后密文 |
| xiaohong | {bcrypt}加密后密文 | {argon2}加密后密文 |

如果查询的password_bcrypt字段的密码，则使用BCryptPasswordEncoder,如果查询的password_argon2字段的密码，则使用Argon2PasswordEncoder

###### 3.自定义校验器方式

###### 4.一个系统使用多种密码校验的方式

比如：登录时使用校验1，登录成功后更新用户的密码为加密2加密后的密码，下次登录使用校验2

###### 5.密码校验器工作的源码流程

#### 九.remeber me 记住我功能

https://yunyanchengyu.blog.csdn.net/article/details/129932284

###### 1.介绍SSC的remeber me的大概流程

1.登录时如果勾选记住我，表单会多一个参数remeber-me: on

2.认证成功后生成cookie信息，保存了用户名和密码，使用SHA-256加密，交给浏览器

3.下次登录时，如果认证没过期，不会验证cookie，如果过期了，会获取cookie的信息重新登录

###### 2.remeber me的功能的源码

###### 3.自定义remeber me相关功能

1.始终开启记住我，开启后，登录时不会校验表单的remeber-me，会直接生成cookie

2.修改勾选记住我后，表单传递的参数名(默认remeber-me)

3.修改当开启remeber me后，认证成功后生成的cookie的相关信息

4.设置加密cookie时，对其添加盐值

5.设置令牌的失效时间

6.自定义 实现记住我的 service类

#### 十.对：四.会话管理 流程的源码解读

https://yunyanchengyu.blog.csdn.net/article/details/129978234

###### 1.SessionAuthenticationStrategy

对HttpSession进行控制、行为扩展:防止会话攻击、并发控制等

###### 2.SessionAuthenticationStrategy的不同实现类介绍

#### 十一.分布式session

https://yunyanchengyu.blog.csdn.net/article/details/129954530

###### 1.使用redis管理spring-session

###### 2.使用分布式session后并发控制失效问题以及解决方法

#### 十二.权限控制

https://yunyanchengyu.blog.csdn.net/article/details/118584275

###### 1.RBAC(Role-Based Access Control)权限模型

基于角色的访问控制

###### 2.SSC的两种权限管理策略

1.基于请求URL：基于请求URL创建授权规则，使用过滤器拦截

2.基于方法：再方法上使用注解，通过AOP进行前后置权限校验

###### 3.权限控制案例

#### 十三.基于请求URL的权限控制源码解析

https://yunyanchengyu.blog.csdn.net/article/details/130031402

###### 1.AuthorizationFilter和其他组件介绍

###### 2.AuthorizationManager以及其实现类

###### 3.根据例子来看基于请求URL的权限检查的源码流程

配置：com.tiglle.ssc.config_授权管理.TiglleSpringSecurityConfig

控制器：com.tiglle.ssc.controller.HelloWordController#testAuthorizationUrl

#### 十四.基于基于方法的权限控制源码解析

https://yunyanchengyu.blog.csdn.net/article/details/130076284

#### 十五.







