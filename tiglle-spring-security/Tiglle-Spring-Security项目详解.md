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

#### 五.验证码功能

###### 1.使用hutools生成验证码，存入redis，每次返回代表此验证码的唯一id和base64的验证码图片数据给前端

com.tiglle.ssc.controller.HelloWordController#generateCaptcha

###### 2.放行验证码生成的链接

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig#defaultSecurityFilterChain

###### 3.创建验证码检验过滤器

com.tiglle.ssc.filter.CaptchaVerifyFilter

###### 4.配置验证码校验过滤器到SSC中

com.tiglle.ssc.config_前后分离.MyTiglleSpringSecurityConfig



