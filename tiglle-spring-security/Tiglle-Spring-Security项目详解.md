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

#### 三.登录页面的渲染过程

##### 1.有关的过滤器

和四个SSC的过滤器有关

1.UsernamePasswordAuthenticationFilter（处理表单登录）

2.DefaultLoginPageGeneratingFilter(配置登录页面)

3.ExceptionTranslationFilter（处理认证授权中的异常）

4.AuthorizationFilter（对请求进行访问权限处理）
![img](https://img-blog.csdnimg.cn/direct/77a33b5a8313436db154dbec6cdacef9.png)

##### 2.http://localhost:800/hello请求的过程

1.一路畅通，到达AuthorizationFilter后，检查发现用户未认证，请求被拦截，并抛出AccessDeniedException异常

2.抛出的 AccessDeniedException 异常会被 ExceptionTranslationFilter 捕获并启动身份验证

3.ExceptionTranslationFilter调用LoginUrlAuthenticationEntryPoint的commence 方法，要求重定向到login页面

4.因此请求变成http://localhost:800/login，浏览器重新发送一次login请求

5./login 请求会被过滤器 DefaultLoginPageGeneratingFilter 拦截，并在过滤器中返回默认的登录页面

#### 四.自定义配置

##### 1.自定义登录页面

编写登录页面：src/main/resources/static/login.html

