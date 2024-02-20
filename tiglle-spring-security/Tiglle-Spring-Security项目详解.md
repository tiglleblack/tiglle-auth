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

###### 3.登录流程

TODO

#### 三.自定义配置

##### 1.自定义登录页面

编写登录页面：src/main/resources/static/login.html

##### 2.自定义各种配置：前后不分离

登录成功后跳转指定的url或者页面

com.tiglle.ssc.config__前后不分离.TiglleSpringSecurityConfig

##### 3.自定义各种配置：前后分离

登录成功后返回JSON数据

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig

##### 4.注销登录

https://yunyanchengyu.blog.csdn.net/article/details/129833839

#### 四.会话管理

https://yunyanchengyu.blog.csdn.net/article/details/129792030

###### 1.可以修改session的生成策略

###### 2.可以设置session的过期时间

###### 3.可以设置session失效后的跳转url

###### 4.默认浏览器关闭清除标识session的JSESSIONID的cookie，可以设置logout后删除JSESSIONID的cookie

###### 5.多用户登录控制

默认SSC允许多个用户再不同的地方登录，可以设置最大会话数，来限制同时登录用户数量。并设置已经登录后其他用户无法登录

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

#### 五.验证码功能

###### 1.使用hutools生成验证码，存入redis，每次返回代表此验证码的唯一id和base64的验证码图片数据给前端

com.tiglle.ssc.controller.HelloWordController#generateCaptcha

###### 2.放行验证码生成的链接

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig#defaultSecurityFilterChain

###### 3.创建验证码检验过滤器

com.tiglle.ssc.filter.CaptchaVerifyFilter

###### 4.配置验证码校验过滤器到SSC中

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig

6.



