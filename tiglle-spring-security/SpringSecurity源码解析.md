#            SpringSecurity源码解析

## 总流程图：

![](https://raw.githubusercontent.com/doocs/source-code-hunter/main/images/SpringSecurity/image-20210811091659121.png)

### 一.SpringSecurity的请求过滤流程图解

##### 1.Servlet的Filter的请求过滤

![img](http://shangyang.me/2018/02/08/spring-security-sca-8-filterchains-01-concept-and-design/web-servlet-filters.png)

##### 2.加入SpringSecurity后的请求过滤

![img](http://shangyang.me/2018/02/08/spring-security-sca-8-filterchains-01-concept-and-design/security-filter-chain-concept.png)

##### 3.将请求交给SecurityFilter过滤的核心类以及流程

ServletFilter-->DelegatingFilterProxy-->FilterChainProxy-->SecurityFilterChain-->SecurityFilters

##### 4.介绍

###### 1.DelegatingFilterProxy

SpringSecurity使用servlet的Filter实现，SpringSecurity有很多Filter，其中之一就是：DelegatingFilterProxy：Servle容器和Spring工厂之间的桥梁，如果想		在Servlet的Filter中使用SpringSecurity的Filter,那么DelegatingFilterProxy就必须再Servlet的Filter中出现，然后通过DelegatingFilterProxy把SSC的Filter注入到Servlet的Filter中

###### 2.FilterChainProxy

FilterChainProxy实现把请求传递给一或多个 SecurityFilterChain 实例进行认证或授权等，并在需要时重定向或返回错误信息。每一个SecurityFilterChain中包含一个或者多个SecurityFilter。

###### 3.SecurityFllterChain

统一管理 Security Filter和 SecurityFllterChain过滤链，当请求到达 FilterChainProxy 时，会根据当前请求匹配SecurityFilterChain，然后将请求依次转发给 SecurityFilterChain 中的 Security Filter

###### 4.SpringSecurity

Spring Security 中最终对请求进行处理的就是某个 SecurityFilterChain 中的 Security Filter，这些Filter都设置为 Bean并且注入到 Spring容器中，且会按照先后顺序执行。

### 二.默认15个核心SecurityFilter的初始化流程

##### 1.十五个核心Filter分别为：

1：DisableEncoderUrlFilter

​	禁止URL重新编码

2：WebAsyncManagerIntegrationFilter

​	将WebAsyncManager与SpringSecurity上下文进行集成

​    	将web的异步处理管理器与SpringSecurity上下文进行集成      

3：SecurityContextHolderFilter

​        获取安全上下文

4：HeaderWriterFilter

​        处理头信息加入响应中

5：CsrfFilter

​        处理CSRF攻击

6：LogoutFilter

​        处理注销登录

7：UsernamePasswordAuthenticationFilter

​        处理表单登录

8：DefaultLoginPageGeneratingFilter

​        配置默认登录页面

9：DefaultLogoutPageGeneratingFilter

​        配置默认注销页面

10：BasicAuthenticationFilter

​        处理 HttpBasic登录

11：RequestCacheAwareFilter

​        处理请求缓存

12：SecurityContextHolderAwareRequestFilter

​        包装原始请求

13：AnonymousAuthenticationFilter

​        配置匿名认证

14：ExceptionTranslationFilter

​        处理认证/授权中的异常

15：AuthorizationFilter

​        处理当前用户是否有权限访问目标资源
##### 2.初始化过程

1.springboot启动时，会进行自动装配(详见:*面试笔记/5-springboot/2.spring boot自动装配流程.md*)，新版会扫描classpath下的文件：

```
classpath:/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

然后加载此文件中的所有自动装配类，其中包含：

```
org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
```

2.SecurityAutoConfiguration使用@Import注解引入了两个类：

```java
@Import({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })
```

3.关键在于SpringBootWebSecurityConfiguration.class这个类

SpringBootWebSecurityConfiguration有两个静态内部类

①SecurityFilterChainConfiguration：会初始化SSC的默认过滤链DefaultSecurityFilterChain到Spring容器(后面讲)

②WebSecurityEnablerConfiguration：初始化15个核心默认过滤器，并交给默认过滤链DefaultSecurityFilterChain

我们来看SpringBootWebSecurityConfiguration这个类，其使用@EnableWebSecurity注解修饰，并且是个空类

```java
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
	@ConditionalOnClass(EnableWebSecurity.class)
	@EnableWebSecurity
	static class WebSecurityEnablerConfiguration {
	}
```

4.@EnableWebSecurity注解也是用了@Import注解，导入了4个类

```java
@Import({ WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class,
		HttpSecurityConfiguration.class })
```

5.关键在于最后一个类：HttpSecurityConfiguration

```java
@Configuration(proxyBeanMethods = false)
class HttpSecurityConfiguration {
@Bean(HTTPSECURITY_BEAN_NAME)
	@Scope("prototype")
	HttpSecurity httpSecurity() throws Exception {
		...................
		HttpSecurity http = new HttpSecurity(this.objectPostProcessor, authenticationBuilder, createSharedObjects());
		...................
		return http;
	}
}
```

此类被@Conguration修饰，配合方法的@Bean属性，可以向Spring容器注入Bean，此类向容器注入了HttpSecurity的实例

HttpSecurity拥有两个私有属性，初始化既赋值

```java
	//存放实例化后的15个SSC核心过滤器
	private List<OrderedFilter> filters = new ArrayList<>();
	//使用构造方法实例化，核心的15个SSC的过滤器就是在这个构造方法被方法其私有属性filterToOrder中的
	private FilterOrderRegistration filterOrders = new FilterOrderRegistration();
```

6.我们来看FilterOrderRegistration的构造方法：

```java
FilterOrderRegistration() {
		Step order = new Step(INITIAL_ORDER, ORDER_STEP);
		put(DisableEncodeUrlFilter.class, order.next());
		put(ForceEagerSessionCreationFilter.class, order.next());
		put(ChannelProcessingFilter.class, order.next());
		order.next(); // gh-8105
		put(WebAsyncManagerIntegrationFilter.class, order.next());
		put(SecurityContextHolderFilter.class, order.next());
		put(SecurityContextPersistenceFilter.class, order.next());
		put(HeaderWriterFilter.class, order.next());
		put(CorsFilter.class, order.next());
		put(CsrfFilter.class, order.next());
		put(LogoutFilter.class, order.next());
		this.filterToOrder.put(
				"org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter",
				order.next());
		this.filterToOrder.put(
				"org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter",
				order.next());
		put(X509AuthenticationFilter.class, order.next());
		put(AbstractPreAuthenticatedProcessingFilter.class, order.next());
		this.filterToOrder.put("org.springframework.security.cas.web.CasAuthenticationFilter", order.next());
		this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter",
				order.next());
		this.filterToOrder.put(
				"org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter",
				order.next());
		put(UsernamePasswordAuthenticationFilter.class, order.next());
		order.next(); // gh-8105
		put(DefaultLoginPageGeneratingFilter.class, order.next());
		put(DefaultLogoutPageGeneratingFilter.class, order.next());
		put(ConcurrentSessionFilter.class, order.next());
		put(DigestAuthenticationFilter.class, order.next());
		this.filterToOrder.put(
				"org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter",
				order.next());
		put(BasicAuthenticationFilter.class, order.next());
		put(RequestCacheAwareFilter.class, order.next());
		put(SecurityContextHolderAwareRequestFilter.class, order.next());
		put(JaasApiIntegrationFilter.class, order.next());
		put(RememberMeAuthenticationFilter.class, order.next());
		put(AnonymousAuthenticationFilter.class, order.next());
		this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter",
				order.next());
		put(SessionManagementFilter.class, order.next());
		put(ExceptionTranslationFilter.class, order.next());
		put(FilterSecurityInterceptor.class, order.next());
		put(AuthorizationFilter.class, order.next());
		put(SwitchUserFilter.class, order.next());
	}
```

他将需要实例化的过滤器放入其类型未Map的私有属性中，key为此过滤器的Class类，value为int的值，应该是过滤器的Order排序，从上到下递增

然后在后续启动中陆续把这些过滤器初始化并放入HttpSecurity.filters属性中，这个过程比较分散，源码不好找，因此：TODO



### 三.SecurityFilterChain过滤链的初始化

1.springboot启动时，会进行自动装配(详见:*面试笔记/5-springboot/2.spring boot自动装配流程.md*)，新版会扫描classpath下的文件：

```
classpath:/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

然后加载此文件中的所有自动装配类，其中包含：

```
org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
```

2.SecurityAutoConfiguration使用@Import注解引入了两个类：

```java
@Import({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })
```

3.关键在于SpringBootWebSecurityConfiguration.class这个类

SpringBootWebSecurityConfiguration有两个静态内部类

①SecurityFilterChainConfiguration：会初始化SSC的默认过滤链DefaultSecurityFilterChain到Spring容器

②WebSecurityEnablerConfiguration：初始化15个核心默认过滤器，并交给默认过滤链DefaultSecurityFilterChain(前面已讲)

4.我们来看SecurityFilterChainConfiguration这个静态内部类

```
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnDefaultWebSecurity
	static class SecurityFilterChainConfiguration {
		@Bean
		@Order(SecurityProperties.BASIC_AUTH_ORDER)
		SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
			//认证所有请求
			http.authorizeHttpRequests().anyRequest().authenticated();
			//开启表单认证
			http.formLogin();
			//开启httpBasic认证
			http.httpBasic();
			return http.build();
		}
	}
```

此类使用@Configuration注解修饰，配合方法的@Bean可以向容器中注入bean，这里注入的是DefaultSecurityFilterChain，并把上面初始化的15个核心过滤器

放入其私有属性filters中

```java
private final List<Filter> filters;
```

至此SSC的默认15个核心过滤器和其组成的过滤链DefaultSecurityFilterChain初始化完成

### 四.DelegatingFilterProxy的初始化

1.springboot启动时，会进行自动装配(详见:*面试笔记/5-springboot/2.spring boot自动装配流程.md*)，新版会扫描classpath下的文件：

```java
classpath:/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

然后加载此文件中的所有自动装配类，其中包含：

```java
org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration
```

2.我们来看SecurityFilterAutoConfiguration：

```java
@AutoConfiguration(after = SecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = Type.SERVLET)
@EnableConfigurationProperties(SecurityProperties.class)
@ConditionalOnClass({ AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class })
public class SecurityFilterAutoConfiguration {

	private static final String DEFAULT_FILTER_NAME = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME;

	@Bean
	@ConditionalOnBean(name = DEFAULT_FILTER_NAME)
	public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration(
			SecurityProperties securityProperties) {
		DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean(
				DEFAULT_FILTER_NAME);
		registration.setOrder(securityProperties.getFilter().getOrder());
		registration.setDispatcherTypes(getDispatcherTypes(securityProperties));
		return registration;
	}
}
```

此类为自动装配类，使用@AutoConfiguration+@Bean的方式向容器注入配置类：DelegatingFilterProxyRegistrationBean

创建DelegatingFilterProxy对象之后，后续代码将DelegatingFilterProxy对象加入到servlet容器的filterchain过滤链中，在请求提交上来之后，通过DelegatingFilterProxy来实现Spring Security的安全功能。

### 五.FilterChainProxy如何装配到DelegatingFilterProxy中

3.我们来看DelegatingFilterProxyRegistrationBean，先看看他的类关系结构



![](E:\DelegatingFilterProxyRegistrationBean.png)

4.其继承了org.springframework.boot.web.servlet.ServletContextInitializer接口，ServletContextInitializer接口的子类在容器启动时，

其onStartup方法会被调用，调用流程：SpringBoot内置Tomcat启动的过程中最终会调用到ServletWebServerApplicationContext的onRefresh

ServletWebServerApplicationContext.onRefresh--->

​	ServletWebServerApplicationContext.createWebServer-->

​				ServletWebServerApplicationContext.getSelfInitializer-->

​						ServletWebServerApplicationContext.selfInitialize

来看看ServletWebServerApplicationContext.selfInitialize方法：

```
private void selfInitialize(ServletContext servletContext) throws ServletException {
		prepareWebApplicationContext(servletContext);
		registerApplicationScope(servletContext);
		WebApplicationContextUtils.registerEnvironmentBeans(getBeanFactory(), servletContext);
		for (ServletContextInitializer beans : getServletContextInitializerBeans()) {
			beans.onStartup(servletContext);
		}
}
```

会循环getServletContextInitializerBeans()的值，其中就包含DelegatingFilterProxyRegistrationBean，会调用其onStartup方法

DelegatingFilterProxyRegistrationBean的onStartup从其父类的父类RegistrationBean中继承来的

```java
	@Override
	public final void onStartup(ServletContext servletContext) throws ServletException {
		String description = getDescription();
		if (!isEnabled()) {
			logger.info(StringUtils.capitalize(description) + " was not registered (disabled)");
			return;
		}
		register(description, servletContext);
	}
```

onStartup方法最终会调用DelegatingFilterProxyRegistrationBean的getFilter()方法，调用链

RegistrationBean.onStartup-->  //DelegatingFilterProxyRegistrationBean的父类的父类

​		AbstractFilterRegistrationBean.getDescription-->  //DelegatingFilterProxyRegistrationBean的父类

​				DelegatingFilterProxyRegistrationBean.getFilter

我们来看看DelegatingFilterProxyRegistrationBean.getFilter方法：

```
	@Override
	public DelegatingFilterProxy getFilter() {
		return new DelegatingFilterProxy(this.targetBeanName, getWebApplicationContext()) {
			@Override
			protected void initFilterBean() throws ServletException {
				// Don't initialize filter bean on init()
			}
		};
	}
```

返回DelegatingFilterProxy类，并且参数为this.targetBeanName，this.targetBeanName的值为"springSecurityFilterChain"

这里把DelegatingFilterProxy的

```
private String targetBeanName;
```

属性设置为"springSecurityFilterChain"

这是DelegatingFilterProxy与SpringSecurityFilterChain的关系，我们再来看DelegatingFilterProxy与FilterChainProxy的关系

DelegatingFilterProxy中的doFilter方法，最终调用了initDelegate方法，此方法会在请求的时候被调用：

DelegatingFilterProxy.doFilter-->

​		DelegatingFilterProxy.initDelegate:

```
    protected Filter initDelegate(WebApplicationContext wac) throws ServletException {
        String targetBeanName = this.getTargetBeanName();
        Assert.state(targetBeanName != null, "No target bean name set");
        Filter delegate = (Filter)wac.getBean(targetBeanName, Filter.class);
        if (this.isTargetFilterLifecycle()) {
            delegate.init(this.getFilterConfig());
        }
        return delegate;
    }
```

String targetBeanName = this.getTargetBeanName();获取的时上面说的"springSecurityFilterChain"的值，然后根据此值从spring容器中获取bean

此bean就是FilterChainProxy，为什么呢，看下一章：DefaultSecurityFilterChain如何装配到FilterChainProxy中

这一篇说的比较模糊，当然也不用看那么仔细，根本用不到

### 六.DefaultSecurityFilterChain如何装配到FilterChainProxy中

1.springboot启动时，会进行自动装配(详见:*面试笔记/5-springboot/2.spring boot自动装配流程.md*)，新版会扫描classpath下的文件：

```
classpath:/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

然后加载此文件中的所有自动装配类，其中包含：

```
org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
```

2.SecurityAutoConfiguration使用@Import注解引入了两个类：

```java
@Import({ SpringBootWebSecurityConfiguration.class, SecurityDataConfiguration.class })
```

3.关键在于SpringBootWebSecurityConfiguration.class这个类

SpringBootWebSecurityConfiguration有两个静态内部类

①SecurityFilterChainConfiguration：会初始化SSC的默认过滤链DefaultSecurityFilterChain到Spring容器(后面讲)

②WebSecurityEnablerConfiguration：初始化15个核心默认过滤器，并交给默认过滤链DefaultSecurityFilterChain

我们来看SpringBootWebSecurityConfiguration这个类，其使用@EnableWebSecurity注解修饰，并且是个空类

```java
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
	@ConditionalOnClass(EnableWebSecurity.class)
	@EnableWebSecurity
	static class WebSecurityEnablerConfiguration {
	}
```

4.@EnableWebSecurity注解也是用了@Import注解，导入了4个类

```java
@Import({ WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class,
		HttpSecurityConfiguration.class })
```

5.关键在于第一个类：WebSecurityConfiguration

此类使用@Configuration+@Autowired的方式，使用set注入方式向WebSecurityConfiguration.securityFilterChains属性注入值

```
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {
	private List<SecurityFilterChain> securityFilterChains = Collections.emptyList();
	
	@Autowired(required = false)
	void setFilterChains(List<SecurityFilterChain> securityFilterChains) {
		this.securityFilterChains = securityFilterChains;
	}
}
```

@Autowired的set注入方式，把参数List<SecurityFilterChain> securityFilterChains注入到this.securityFilterChains中

因此这个参数的值是需要从Spring容器中获取。

前面讲了SSC的默认SecurityFilterChain的初始化，为DefaultSecurityFilterChain，因此这里注入的就是DefaultSecurityFilterChain(Emmmmmmm)

6.然后看WebSecurityConfiguration.springSecurityFilterChain方法：方法中调用了别的方法，调用链：

WebSecurityConfiguration.springSecurityFilterChain-->

​		AbstractSecurityBuilder.build-->

​				AbstractConfiguredSecurityBuilder.doBuild-->

​						WebSecurity.performBuild:

其中有个for循环

```java
		for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : this.securityFilterChainBuilders) {
			//重要的是这句securityFilterChainBuilder.build()返回的就是DefaultSecurityFilterChain
			SecurityFilterChain securityFilterChain = securityFilterChainBuilder.build();
			
			//然后把DefaultSecurityFilterChain放入securityFilterChains中
			securityFilterChains.add(securityFilterChain);
			
			requestMatcherPrivilegeEvaluatorsEntries
				.add(getRequestMatcherPrivilegeEvaluatorsEntry(securityFilterChain));
		}
		if (this.privilegeEvaluator == null) {
			this.privilegeEvaluator = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
					requestMatcherPrivilegeEvaluatorsEntries);
		}
		
		//最后把securityFilterChains交给FilterChainProxy
		FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
		return result;
```

看注释，至此DefaultSecurityFilterChain注入到了FilterChainProxy中，并把FilterChainProxy对象返回到springSecurityFilterChain方法，然后使用@Bean的方式注入到spring容器：

```java
@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
public Filter springSecurityFilterChain() throws Exception {
    ....................
    return this.webSecurity.build();//返回值为FilterChainProxy
}
```

至此SecurityFilterChain注入到了FilterChainProxy中

### 七.SpringSecurity的Filter的工作过程

1.请求会先到达DelegatingFilterProxy，然后递归调用15个SecurityFilter的doFilterInternal方法，调用链：

DelegatingFilterProxy.doFilter-->

 DelegatingFilterProxy.invokeDelegate-->

  FilterChainProxy.doFilter-->

   FilterChainProxy.doFilterInternal-->

​    FilterChainProxy.VirtualFilterChain.doFilter-->

FilterChainProxy.VirtualFilterChain的doFilter就是递归调用的方法:

```java
		@Override
		public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
			.......
            //nextFilter的值每次递归都是不同的Filter，15个SecurityFilter依次递归
			nextFilter.doFilter(request, response, this);
		}
```

这里分别调用15个Filter的doFilter方法，其中大部分都是继承自父类OncePerRequestFilter，所以调用父类的doFilter方法，在父类的doFilter方法中，调用子类重写的doFilterInternal方法，因此，会分别调用15个SecurityFilter的doFilterInternal方法

### 七.登录页面的渲染过程

#### 一.登录页面的渲染过程

这里只是讲的大概，详细请看：

https://yunyanchengyu.blog.csdn.net/article/details/129812970

##### 1.有关的过滤器

和四个SSC的过滤器有关

1.UsernamePasswordAuthenticationFilter（处理表单登录）

2.DefaultLoginPageGeneratingFilter(配置登录页面)

3.ExceptionTranslationFilter（处理认证授权中的异常）

4.AuthorizationFilter（对请求进行访问权限处理）
![img](https://img-blog.csdnimg.cn/direct/77a33b5a8313436db154dbec6cdacef9.png)

##### 2.http://localhost:800/hello请求的过程

1.请求经过AnonymousAuthenticationFilter，从SecurityContext中获取用户信息，因为未认证，所以获取不到，会创建匿名的Authentication

当登录以后会把用户信息放入SecurityContext(前面的UsernamePasswordAuthenticationFilter处理的)，再经过AnonymousAuthenticationFilter时返回的是认证过的Authentication

1.到达AuthorizationFilter后，检查发现为匿名用户，判定当前请求无权访问，抛出AccessDeniedException异常

2.抛出的 AccessDeniedException 异常会被 ExceptionTranslationFilter(AuthorizationFilter的上一次过滤器) 捕获并启动身份验证

3.ExceptionTranslationFilter调用LoginUrlAuthenticationEntryPoint的commence 方法，要求重定向到login页面

4.因此请求变成http://localhost:800/login，浏览器重新发送一次login请求

5./login 请求会被过滤器 DefaultLoginPageGeneratingFilter 拦截，判断如果是/login请求，会调用本类的generateLoginPageHtml方法，生产登录页面

6.然后设置response的ContentType=text/html,使用response.getWriter().write(loginPageHtml)写入登录页面，然后return，不继续后续流程，直接返回

![在这里插入图片描述](https://img-blog.csdnimg.cn/b9474a5df47f4903b6ccecbac16d884c.png)

/helllow会经过UsernamePassowordAuthenticationFilter，但是此过滤器的只处理，post请求，并且/login的请求，因此会继续向下

### 八.默认用户名和密码的生成过程

##### 1.初始化用户名和密码

1.springboot启动时，会进行自动装配(详见:*面试笔记/5-springboot/2.spring boot自动装配流程.md*)，新版会扫描classpath下的文件：

```
classpath:/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

然后加载此文件中的所有自动装配类，其中包含：

```
org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
```

2.SecurityAutoConfiguration使用@EnableConfigurationProperties将指定的Properties类注册为bean：SecurityProperties

我们来看SecurityProperties

```
@ConfigurationProperties(prefix = "spring.security")
public class SecurityProperties {
	//默认用户，使用下面的静态内部类
	private final User user = new User();
	//静态内部类
	public static class User {

		private String name = "user";

		private String password = UUID.randomUUID().toString();
		//此用户的角色信息
		private List<String> roles = new ArrayList<>();
	}
}
```

此Properties类使用@ConfigurationProperties指定配置类的前缀，并且拥有User对象，默认为静态内部类，静态内部内的name和password属性的默认值，就是SpringSecurity的默认默认用户名和密码，roles属性存放了用户的角色信息，默认为空集合。此时SecurityProperties的User类已经初始化并拥有值

我们也可以通过在配置文件配置这三个属性的值，修改默认用户名和密码，添加角色

```
spring.security.user.name=admin
spring.security.user.password==Aa123456
spring.security.user.roles=superadmin,guest,manager
```

##### 2.将初始化的用户名和密码放入缓存，后面认证的时候会从缓存中取

1.还是springboot的自动装配 ,springboot启动时，会进行自动装配(详见:*面试笔记/5-springboot/2.spring boot自动装配流程.md*)，新版会扫描classpath下的文件：

```
classpath:/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
```

然后加载此文件中的所有自动装配类，其中包含：

```
org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration
```

我们来看看UserDetailsServiceAutoConfiguration：

```
@AutoConfiguration
....省略某注解........
public class UserDetailsServiceAutoConfiguration {
	....省略某属性........
	@Bean
	public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
			ObjectProvider<PasswordEncoder> passwordEncoder) {
		//从SecurityProperties中获取User信息
		SecurityProperties.User user = properties.getUser();
		//获取角色信息
		List<String> roles = user.getRoles();
		//1.将SecurityProperties中的user信息构建为UserDetails类型，并作为构造函数的参数
		//2.向容器中注入默认的UserDetailsService类
		return new InMemoryUserDetailsManager(User.withUsername(user.getName())
			.password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
			.roles(StringUtils.toStringArray(roles))
			.build());
	}
```

可以看到使用@AutoConfiguration+@Bean的方式，向容器中注入了InMemoryUserDetailsManager，此类为UserDetailsService接口的是实现类，UserDetailsService很重要，SSC认证的时候需要通过他获取真实的用户信息，我们可以实现它来自定义真实用户的获取方式

我们先来看看InMemoryUserDetailsManager这个类：

```
public class InMemoryUserDetailsManager implements UserDetailsManager, UserDetailsPasswordService {
	//存放用户信息的缓存，后面认证用户的时候会从这个缓存中获取用户信息
	private final Map<String, MutableUserDetails> users = new HashMap<>();
	//此构造函数将用户放入上面的缓存，key为user的name的值
	public InMemoryUserDetailsManager(UserDetails... users) {
		for (UserDetails user : users) {
			//将用户放入users缓存
			createUser(user);
		}
	}
	//被调用后将用户放入users缓存
	@Override
	public void createUser(UserDetails user) {
		Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
		this.users.put(user.getUsername().toLowerCase(), new MutableUser(user));
	}
	
}
```

InMemoryUserDetailsManager的构造函数接收UserDetails类型的参数，因此注入InMemoryUserDetailsManager时，会把从SecurityProperties构建为UserDetails然后传入构造函数，然后放入InMemoryUserDetailsManager的Map属性users的缓存中，key为UserDetails的username的值

此缓存为Map，因此不止存放一个用户信息

OK，此时SSC的默认用户信息已经放入缓存，key为username=admin

##### 至于怎么从缓存获取然后验证的，我们看下一章：七.SpringSecurity的请求处理流程

### 七.SpringSecurity的请求处理流程

请求先认证，在授权(检查权限)

#### 1.认证流程

##### 1.认证授权设置

默认SSC会对formLogin、httpBasic的认证方式进行认证，并且检查所有请求，再 三.SecurityFilterChain过滤链的初始化 的时候设置的

我们可以向容器中注入DefaultSecurityFilterChain来自定义配置，如：

```java
//6.0之前是继承WebSecurityConfigurerAdapter来完成
@Configuration
public class TiglleSpringSecurityConfig {
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests()
                //放行的资源，不用认证直接访问
                .requestMatchers("/test").permitAll()
                .requestMatchers("/test2").permitAll()
            	//其他所有请求都认证
                .anyRequest().authenticated();
        //开启表单认证
        FormLoginConfigurer<HttpSecurity> httpSecurityFormLoginConfigurer = httpSecurity.formLogin();
        //指定表单认证的登录页面
        httpSecurityFormLoginConfigurer.loginPage("/login");
        //开启httpBase认证
        httpSecurity.httpBasic();
        return httpSecurity.build();
    }
}
```

##### 2.表单认证

/login请求会被UsernamePasswordAuthenticationFilter拦截(Post的/login请求)，执行器doFilter方法(从其父类AbstractAuthenticationProcessingFilter继承的方法),调用链：

AbstractAuthenticationProcessingFilter.doFilter ①  

 ->UsernamePasswordAuthenticationFilter.attemptAuthentication ②  封装username和password为Authentication票据

   ->ProviderManager.authenticate ③ 查找合适的ProviderManager认证Authentication票据

​    ->AbstractUserDetailsAuthenticationProvider.authenticate ④ 正真认证票据的地方，根据用户名查找密码进行认证

​     ->DaoAuthenticationProvider.additionalAuthenticationChecks ⑤ 校验密码

###### 1.来看看第②步：UsernamePasswordAuthenticationFilter.attemptAuthentication方法（可直接跳过代码看总结）

```java
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
        //如果是/login，但不是post方法，抛出异常
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
        //从request中获取username和password的值，去除空格
		String username = obtainUsername(request);
		username = (username != null) ? username.trim() : "";
		String password = obtainPassword(request);
		password = (password != null) ? password : "";
        //封装成Authentication，并标记此Authentication为未认证的状态(AbstractAuthenticationToken.authenticated=false)
        //类关系：UsernamePasswordAuthenticationToken->AbstractAuthenticationToken->Authentication
		UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username,
				password);
		// 设置UsernamePasswordAuthenticationToken的details信息
        //AbstractAuthenticationToken.details=WebAuthenticationDetails
		setDetails(request, authRequest);
        //调用认证管理器ProviderManager进行认证，并返回认证后的Authentication
		return this.getAuthenticationManager().authenticate(authRequest);
	}
```

总结：

①判断不是post的/login，抛出异常

②从request中获取username和password，并封装成票据Authentication：UsernamePasswordAuthenticationToken，是否认证属性

```
AbstractAuthenticationToken.authenticated=false//是否认证
UsernamePasswordAuthenticationToken.principal=username的值
UsernamePasswordAuthenticationToken.credentials=password的值
```

并包含IP，sessionID等信息

③设置UsernamePasswordAuthenticationToken的details信息：AbstractAuthenticationToken.details=WebAuthenticationDetails

④调用认证管理器ProviderManager进行认证，并返回认证后的Authentication票据信息

###### 2.来看看第③步：ProviderManager.authenticate：

```java
@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ..........省略某些代码...........
    //第一次调用先从ProviderManager.providers中找处理UsernamePasswordAuthenticationToken类型的票据的Provider
    //第二次递归也会从ProviderManager.providers中找处理UsernamePasswordAuthenticationToken类型的票据的Provider
    for (AuthenticationProvider provider : getProviders()) {
       //第一次调用时providers中只有AnonymousAuthenticationProvider，处理AnonymousAuthenticationToken类型的票据，不支持
       //第二次递归时providers中有DaoAuthenticationProvider(很神奇TODO)，刚好处理UsernamePasswordAuthenticationToken类型的票据
       if (!provider.supports(toTest)) {
          continue;
       }
       //第一次调用会被continue，不会走这里
       //第二次递归会调用DaoAuthenticationProvider.authenticate方法（从父类AbstractUserDetailsAuthenticationProvider继承的方法）
       result = provider.authenticate(authentication);
      ..........省略某些代码...........
    //如果前面没找到支持UsernamePasswordAuthenticationToken类型的票据的Provider
    if (result == null && this.parent != null) {
       try {
          //递归调用本方法authenticate
          parentResult = this.parent.authenticate(authentication);
          result = parentResult;
       }
    }
    //返回认证后的Authentication票据
    return result;
    }
```

总结：

①此方法使用递归的方式寻找符合当前类型的AuthenticationToken的提供者进行处理：

DaoAuthenticationProvider->UsernamePasswordAuthenticationToken

AnonymousAuthenticationProvider->AnonymousAuthenticationToken

<span style="color: red;">②因此会调用DaoAuthenticationProvider.authenticate方法</span>，从父类AbstractUserDetailsAuthenticationProvider继承的方法

③最后返回处理过后的Authentication票据信息

###### 3.我们来看看第④步：AbstractUserDetailsAuthenticationProvider..authenticate:

```
@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		//只处理UsernamePasswordAuthenticationToken类型的票据token，如果不是抛IllegalArgumentException异常
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
				() -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
						"Only UsernamePasswordAuthenticationToken is supported"));
		//从票据中获取principal信息，也就是username的值
		String username = determineUsername(authentication);
		boolean cacheWasUsed = true;
		//从AbstractUserDetailsAuthenticationProvider.userCache中获取用户，第一次没值，校验成功会放入此属性中
		UserDetails user = this.userCache.getUserFromCache(username);
		if (user == null) {
			cacheWasUsed = false;
			try {
				//根据username从数据库、缓存、redis中获取(具体看我们的自定义的UserDetailsService的实现)
				//如果没有自定义默认为InMemoryUserDetailsManager这个子类：从非持久缓存中获取
				//从InMemoryUserDetailsManager.users属性中获取user(Map类型)
				//什么时候存入的user看：八.默认用户名和密码的生成过程
				//返回为UserDetails类型的user
				user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
			}
			//根据username找不到用户，抛异常：UsernameNotFoundException
			catch (UsernameNotFoundException ex) {
				this.logger.debug("Failed to find user '" + username + "'");
				if (!this.hideUserNotFoundExceptions) {
					throw ex;
				}
				throw new BadCredentialsException(this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
			}
			Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
		}
		try {
			this.preAuthenticationChecks.check(user);
			//校验密码
			additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		}
		...........省略某些代码.............
		//校验失败，抛AuthenticationException异常
		catch (AuthenticationException ex) {
			if (!cacheWasUsed) {
				throw ex;
			}
		}
		//校验成功，user放入AbstractUserDetailsAuthenticationProvider.userCache缓存中
		if (!cacheWasUsed) {
			this.userCache.putUserInCache(user);
		}
		...........省略某些代码.............
		//创建检验成功的Authentication票据，还是UsernamePasswordAuthenticationToken，AbstractAuthenticationToken.authenticated=true
		return createSuccessAuthentication(principalToReturn, authentication, user);
	}
```

总结：

①如果不是UsernamePasswordAuthenticationToken类型的Authentication票据，抛IllegalArgumentException异常

②从UsernamePasswordAuthenticationToken中获取principal信息，也就是username的值

③从AbstractUserDetailsAuthenticationProvider.userCache中获取用户，第一次没值，校验成功会放入此属性中

③使用UserDetailsService根据username的值从数据库、缓存等获取用户信息，默认使用的UserDetailsService的子类InMemoryUserDetailsManager，也有其他可以使用的实现类：

1.InMemoryUserDetailsManager 非持久缓存中获取，默认实现，从InMemoryUserDetailsManager.users中获取

​	什么时候放入user信息，看：八.默认用户名和密码的生成过程

2.CachingUserDetailsService 从 自定义缓存中获取，可实现NullUserCache自定义缓存

3.JdbcUserDetailsManager 从某数据源中获取(数据库)

4.我们可以自定义UserDetailsService的实现类，注入容器中，自定义loadUserByUsername方法

④将获取到的用户封装为UserDetails类型并返回（我们可以自定义UserDetails的实现类返回我们自定义的用户信息）

⑤根据username找不到用户，抛异常：UsernameNotFoundException

⑥使用additionalAuthenticationChecks.additionalAuthenticationChecks方法校验密码

⑦如果密码校验失败抛出AuthenticationException异常

⑧校验成功，user放入AbstractUserDetailsAuthenticationProvider.userCache缓存中

⑧校验成功返回检验成功的Authentication票据：还是UsernamePasswordAuthenticationToken，AbstractAuthenticationToken.authenticated=true

###### 4.来看看第⑤步：<span style="color: red;">DaoAuthenticationProvider.additionalAuthenticationChecks(比较密码)</span>

```
	@Override
	@SuppressWarnings("deprecation")
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		//如果密码为null，抛出BadCredentialsException异常，AuthenticationException的子类
		if (authentication.getCredentials() == null) {
			this.logger.debug("Failed to authenticate since no credentials provided");
			throw new BadCredentialsException(this.messages
				.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
		String presentedPassword = authentication.getCredentials().toString();
		//最终会使用equals的方式对比两个密码  表单输入的值 equals 数据库的值
		//如果对比失败，抛出BadCredentialsException，AuthenticationException的子类
		if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
			this.logger.debug("Failed to authenticate since password does not match stored value");
			throw new BadCredentialsException(this.messages
				.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}
	}
```

总结：

①如果密码为null，抛出BadCredentialsException

②最终会使用equals的方式对比两个密码  表单输入的值 equals 数据库的值

③如果对比失败，抛出BadCredentialsException，AuthenticationException的子类

④最终抛出的BadCredentialsException会被AbstractUserDetailsAuthenticationProvider..authenticate捕获，并抛出，然后被ProviderManager.authenticate捕获，也抛出，然后被AbstractAuthenticationProcessingFilter.doFilter方法捕获，并调用AbstractAuthenticationProcessingFilter.unsuccessfulAuthentication方法处理校验失败：

1.让浏览器重定向到/login?error

2.向session中设置attribute：SPRING_SECURITY_LAST_EXCEPTION=BadCredentialsException(用户名密码错误)

3.浏览器重新发起/login?error请求，返回登录失败的页面

⑤如果校验成功，回到AbstractUserDetailsAuthenticationProvider.authenticate的第⑤步，返回校验成功的token信息

###### 5.此时可以回到起点：AbstractAuthenticationProcessingFilter.doFilter,前面没讲这个代码，这里讲：

```java
private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);
			return;
		}
		try {
			Authentication authenticationResult = attemptAuthentication(request, response);
			if (authenticationResult == null) {
				// return immediately as subclass has indicated that it hasn't completed
				return;
			}
            //会话策略处理
            //1.CsrfAuthenticationStrategy: ：它负责在执行认证请求之后, 删除旧的令牌, 生成新的，确保每次请求之后, 都得到更新
            //2.ChangeSessionIdAuthenticationStrategy：主要是使用HttpServletRequest.changeSessionId()方法修改sessionID来防止会话固定攻击。
			this.sessionStrategy.onAuthentication(authenticationResult, request, response);
			// Authentication success
			if (this.continueChainBeforeSuccessfulAuthentication) {
				chain.doFilter(request, response);
			}
            //验证成功的最终处理
			successfulAuthentication(request, response, chain, authenticationResult);
		}
		catch (InternalAuthenticationServiceException failed) {
			this.logger.error("An internal error occurred while trying to authenticate the user.", failed);
            //验证失败的最终处理
			unsuccessfulAuthentication(request, response, failed);
		}
		catch (AuthenticationException ex) {
			// Authentication failed
			unsuccessfulAuthentication(request, response, ex);
		}
	}
```

总结：

1.验证成功的处理AbstractAuthenticationProcessingFilter.successfulAuthentication

①会话策略处理：

1.CsrfAuthenticationStrategy: ：它负责在执行认证请求之后, 删除旧的令牌, 生成新的，确保每次请求之后, 都得到更新

2.ChangeSessionIdAuthenticationStrategy：主要是使用HttpServletRequest.changeSessionId()方法修改sessionID来防止会话固定攻

②AbstractAuthenticationProcessingFiltersuccessfulAuthentication方法：

```java
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
        //封装UsernamePasswordAuthenticationToken的票据为SecurityContext
		SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
		context.setAuthentication(authResult);
        //设置SecurityContext到ThreadLocal中
		this.securityContextHolderStrategy.setContext(context);
        //设置到SecurityContext到session中：SPRING_SECURITY_CONTEXT=SecurityContext
		this.securityContextRepository.saveContext(context, request, response);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
		}
        //NullRememberMeServices.loginSuccess方法处理remeber，但是方法是空方法
		this.rememberMeServices.loginSuccess(request, response, authResult);
		if (this.eventPublisher != null) {
            //发布登录成功事件
			this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
		}
        //让浏览器重定向到登陆前的哪个url
		this.successHandler.onAuthenticationSuccess(request, response, authResult);
	}
```

总结：

①.封装UsernamePasswordAuthenticationToken的票据为SecurityContext

②设置SecurityContext到ThreadLocal和session中

③NullRememberMeServices.loginSuccess方法处理remeber，但是方法是空方法

④发布登录成功事件，让浏览器重定向到登陆前的哪个url

2.验证失败的处理：AbstractAuthenticationProcessingFilter.unsuccessfulAuthentication

```java
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
        //清除securityContext信息
		this.securityContextHolderStrategy.clearContext();
		this.logger.trace("Failed to process authentication request", failed);
		this.logger.trace("Cleared SecurityContextHolder");
		this.logger.trace("Handling authentication failure");
        //remeber处理
		this.rememberMeServices.loginFail(request, response);
        //让浏览器重定向到/login?error
		this.failureHandler.onAuthenticationFailure(request, response, failed);
	}
```

SimpleUrlAuthenticationFailureHandler.onAuthenticationFailure

```java
@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		if (this.defaultFailureUrl == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Sending 401 Unauthorized error since no failure URL is set");
			}
			else {
				this.logger.debug("Sending 401 Unauthorized error");
			}
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			return;
		}
        //设置失败原因到session:账号密码错误
		saveException(request, exception);
		if (this.forwardToDestination) {
			this.logger.debug("Forwarding to " + this.defaultFailureUrl);
			request.getRequestDispatcher(this.defaultFailureUrl).forward(request, response);
		}
		else {
            //重定向到/login?error
			this.redirectStrategy.sendRedirect(request, response, this.defaultFailureUrl);
		}
	}
```

总结：

①.让浏览器重定向到/login?error

②.向session中设置attribute：SPRING_SECURITY_LAST_EXCEPTION=BadCredentialsException(用户名密码错误)

③.浏览器重新发起/login?error请求

④浏览器重新发起/login?error请求会被DefaultLoginPageGeneratingFilter处理，又重定向到登录页，并显示错误信息：
