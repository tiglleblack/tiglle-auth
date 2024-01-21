#### 第一步：初始项目

​    不添加spring-boot-starter-security的时候，访问控制器：http://localhost:8080/hello，可以随便访问

#### 第二步：添加SpringSecurity依赖

######     1.添加spring-boot-starter-security之后，什么都不做，启动的时候，控制台提示：

```shell
Using generated security password: 3ae5a6fb-c108-403c-ace2-63273408c5b3

This generated password is for development use only. Your security configuration must be updated before running your application in production.
```

###### 2.再次访问控制器：http://localhost:8080/hello，出现登录页面，使用账密：user,1029d33d-f87f-412d-bb4f-0da8ebaca8a8登录后成功访问

#### 第三步：DelegatingFilterProxy原理

###### 1.原理：DelegatingFilterProxy：

​		SpringSecurity使用servlet的Filter实现，SpringSecurity有很多Filter，其中之一就是：DelegatingFilterProxy：Servle容器和Spring工厂之间的桥梁，如果想		在Servlet的Filter中使用SpringSecurity的Filter,那么DelegatingFilterProxy就必须再Servlet的Filter中出现，然后通过DelegatingFilterProxy把SSC的Filter注入到Servlet的Filter中

###### 2.DelegatingFilterProxy的结构：

​        DelegatingFilterProxy 类继承于抽象类 GenericFilterBean 间接 implements 了javax.servlet.Filter 接口。Servlet容器启动就会加载好这个类。借助他可以实现普通的Filter拦截到的Http请求交由FilterChainProxy。

​		所以，DelegatingFilterProxy本质就是一个过滤器，本质上和FilterChain中的Filter没有任何区别。
​		原生的Filter运行在Servlet容器里边也就是Tomcat容器当中，而Spring的所书写的过滤器属于Spring工厂。Spring工厂中的过滤器是没有办法在容器层拦截Http请求并进行干预的，但是原生Filter就可以做到直接在容器层拦截Http请求并进行干预，就比如DelegatingFilterProxy(implements 了javax.servlet.Filter 接口,所以也是一个容器层过滤器)，所以借助它，Spring当中的Filter就可以过滤和干预Http请求了。

###### 3.DelegatingFilterProxy需要借助于

##### FilterChainProxy

###### 类将请求转给Spring中的Bean Filter进行处理。

###### 4.示意图：

![](https://img-blog.csdnimg.cn/799997bbd3514ccabf0428aa4e8b7553.png)

注意1：注意：一个项目可能不止一个Filter，多个Filter形成FilterChain，所以也可以说是DelegatingFilterProxy搭建起来了Servler的Filter Chain和Spring Security的FilterChain之间的桥梁。后续重点说FilterChain

#### 第四步：FilterChainProxy原理

######     1.FilterChainProxy的结构

​         FilterChainProxy 类继承于抽象类 GenericFilterBean 间接 implements 了javax.servlet.Filter 接口。所以，FilterChainProxy本质就也是一个Servlet的Filter，本质上和FilterChain中的Filter没有任何区别。

######     2.作用1：

​        FilterChainProxy实现把请求传递给一或多个 SecurityFilterChain 实例进行认证或授权等，并在需要时重定向或返回错误信息。每一个SecurityFilterChain中包含一个或者多个SecurityFilter。
![](https://img-blog.csdnimg.cn/b2fd84c8cde54da6807e47863db86e15.png)

#### 第五步：SecurityFilterChain原理

###### 1.作用

​		 SecurityFilterChain和 Servlet 中的 FilterChain 一样，同样维护了很多 Filter，这些 Filter 由SpringSecurity 提供，每个 Filter 具有不同的职能
​		Spring Security支持添加1或多个 SecurityFilterChain，每个SecurityFilterChain负责不同的请求(比如依据请求地址进行区分) ，这样可以为不同的请求设置不同的认证规则。
![](https://img-blog.csdnimg.cn/7126aef2685c456ab9ed591c33b69f1f.png)

######     2.流程：

​        FilterChainProxy 是顶层管理者，统一管理 Security Filter和 SecurityFllterChain过涉器链
​        当请求到达 FilterChainProxy 时，会根据当前请求匹配SecurityFilterChain，然后将请求依次转发给 SecurityFilterChain 中的 Security Filter

#### 第六步：Security Filters

​		Spring Security 中最终对请求进行处理的就是某个 SecurityFilterChain 中的 Security Filter，这些Filter都设置为 Bean并且注入到 Spring容器中，且会按照先后顺序执行。

​		下面展示 Spring Security 中给我们提供的过滤器，以及默认情况下会被加载的过滤器

##### 1.Spring Security默认过滤器：通过初始化FilterOrderRegistration，执行其构造函数初始化一些Security Filter到Spring容器

```java
FilterOrderRegistration() {
        Step order = new Step(100, 100);
        this.put(DisableEncodeUrlFilter.class, order.next());
        this.put(ForceEagerSessionCreationFilter.class, order.next());
        this.put(ChannelProcessingFilter.class, order.next());
        order.next();
        this.put(WebAsyncManagerIntegrationFilter.class, order.next());
        this.put(SecurityContextHolderFilter.class, order.next());
        this.put(SecurityContextPersistenceFilter.class, order.next());
        this.put(HeaderWriterFilter.class, order.next());
        this.put(CorsFilter.class, order.next());
        this.put(CsrfFilter.class, order.next());
        this.put(LogoutFilter.class, order.next());
        this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter", order.next());
        this.filterToOrder.put("org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter", order.next());
        this.put(X509AuthenticationFilter.class, order.next());
        this.put(AbstractPreAuthenticatedProcessingFilter.class, order.next());
        this.filterToOrder.put("org.springframework.security.cas.web.CasAuthenticationFilter", order.next());
        this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter", order.next());
        this.filterToOrder.put("org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter", order.next());
        this.put(UsernamePasswordAuthenticationFilter.class, order.next());
        order.next();
        this.put(DefaultLoginPageGeneratingFilter.class, order.next());
        this.put(DefaultLogoutPageGeneratingFilter.class, order.next());
        this.put(ConcurrentSessionFilter.class, order.next());
        this.put(DigestAuthenticationFilter.class, order.next());
        this.filterToOrder.put("org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter", order.next());
        this.put(BasicAuthenticationFilter.class, order.next());
        this.put(RequestCacheAwareFilter.class, order.next());
        this.put(SecurityContextHolderAwareRequestFilter.class, order.next());
        this.put(JaasApiIntegrationFilter.class, order.next());
        this.put(RememberMeAuthenticationFilter.class, order.next());
        this.put(AnonymousAuthenticationFilter.class, order.next());
        this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter", order.next());
        this.put(SessionManagementFilter.class, order.next());
        this.put(ExceptionTranslationFilter.class, order.next());
        this.put(FilterSecurityInterceptor.class, order.next());
        this.put(AuthorizationFilter.class, order.next());
        this.put(SwitchUserFilter.class, order.next());

```

##### 2.比较核心的几个BeanFilter(SecurityFilter)(不一定是上面的FilterOrderRegistration初始化的)

###### 1：DisableEncoderUrlFilter：

​		禁止URL重新编码，默认程序启动就会加载。

###### 2：WebAsynManagerIntegrationFilter：

​		将WebAsyncManager(web的异步处理管理器)与SpringSecurity上下文进行集成。默认程序启动就会加载。

###### 3：SecurityContextHolderFilter:

​		获取安全上下文，默认程序启动就会加载。

###### 4：HeaderWriterFilter:

  		处理头信息加入响应中，默认程序启动就会加载。

###### 5：CsrfFilter:

​		处理CSRF攻击，默认程序启动就会加载。

###### 6：LogoutFilter

​        处理注销登录，默认程序启动就会加载。

###### 7：UsernamePasswordAuthenticationFilter

​        处理表单登录，默认程序启动就会加载。

###### 8：DefaultLoginPageGeneratingFilter

​        配置默认登录页面，默认程序启动就会加载。

###### 9：DefaultLogoutPageGeneratingFilter

​        配置默认注销页面，默认程序启动就会加载。

###### 10：BasicAuthenticationFilter

​        处理 HttpBasic登录，默认程序启动就会加载。

###### 11：RequestCacheAwareFilter

​        处理请求缓存，默认程序启动就会加载。

###### 12：SecurityContextHolderAwareRequestFilter

​        包装原始请求，默认程序启动就会加载。

###### 13：AnonymousAuthenticationFilter

​        配置匿名认证，默认程序启动就会加载。

###### 14：ExceptionTranslationFilter

​        处理认证/授权中的异常，默认程序启动就会加载。

###### 15：AuthorizationFilter

 		处理当前用户是否有权限访问目标资源，默认程序启动就会加载。

#### 第七步：SecurityFilerChain

​		Spring Security 提供了30 多个过滤器，都属于SecurityFilerChain这个过滤链，具体源码可以查看DefaultSecurityFilterChain(SecurityFilerChain的子类)

​		这些配置通过WebSecurityConfiguration 进行配置

#### 第八步：spring-security的自动装配

##### 1.新版自动装配原理(2.7及更高)

​	springboot启动的时候，会递归处理主启动类的@Import注解，其中包含AutoConfigurationImportSelector类，会扫描classpath下所有的

​	META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports文件，将文件中指定的所有类加载进bdm，然后实例化

##### 2.spring-security的自动装配

spring-boot-autoconfigure包中包含文件：

```apl
spring-boot-autoconfigure-3.0.12.jar!\META-INF\spring\org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

其中包含很多spring-security的自动装配类,例如：

```apl
org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration
org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration
org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration
org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration
org.springframework.boot.autoconfigure.security.rsocket.RSocketSecurityAutoConfiguration
org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyAutoConfiguration
.........
```

##### 3.核心自动装配类：SecurityAutoConfiguration

此类使用@import引入了两个类，处理自动配置类时会对@import引入的类进行处理

@Import({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })

###### 比较重要的是：SpringBootWebSecurityConfiguration

向容器中注入了SecurityFilterChain，SecurityFilterChain的作用可以看 第七步

```java
		@Bean
		@Order(SecurityProperties.BASIC_AUTH_ORDER)
		SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
            //任意Http请求都会被认证拦截
			http.authorizeHttpRequests().anyRequest().authenticated();
            //认证的时候支持form表单认证
			http.formLogin();
            //http的basic认证
			http.httpBasic();
			return http.build();
		}
```

可以看到SecurityFilterChain拦截了所有的请求，所以 第二步 引入以来后所有请求都需要登录

##### TODO:第六篇最后一点默认认证方式的条件，要不要看

