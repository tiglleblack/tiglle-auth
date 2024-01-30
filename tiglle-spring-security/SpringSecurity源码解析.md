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

15个核心Filter分别为：

1：DisableEncoderUrlFilter

​		禁止URL重新编码，默认程序启动就会加载。

2：WebAsyncManagerIntegrationFilter

​		将WebAsyncManager与SpringSecurity上下文进行集成。默认程序启动就会加载。

​    	将web的异步处理管理器与SpringSecurity上下文进行集成      

3：SecurityContextHolderFilter

​        获取安全上下文，默认程序启动就会加载。

4：HeaderWriterFilter

​        处理头信息加入响应中，默认程序启动就会加载。

5：CsrfFilter

​        处理CSRF攻击，默认程序启动就会加载。

6：LogoutFilter

​        处理注销登录，默认程序启动就会加载。

7：UsernamePasswordAuthenticationFilter

​        处理表单登录，默认程序启动就会加载。

8：DefaultLoginPageGeneratingFilter

​        配置默认登录页面，默认程序启动就会加载。

9：DefaultLogoutPageGeneratingFilter

​        配置默认注销页面，默认程序启动就会加载。

10：BasicAuthenticationFilter

​        处理 HttpBasic登录，默认程序启动就会加载。

11：RequestCacheAwareFilter

​        处理请求缓存，默认程序启动就会加载。

12：SecurityContextHolderAwareRequestFilter

​        包装原始请求，默认程序启动就会加载。

13：AnonymousAuthenticationFilter

​        配置匿名认证，默认程序启动就会加载。

14：ExceptionTranslationFilter

​        处理认证/授权中的异常，默认程序启动就会加载。

15：AuthorizationFilter

​        处理当前用户是否有权限访问目标资源，默认程序启动就会加载。

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
			http.authorizeHttpRequests().anyRequest().authenticated();
			http.formLogin();
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

DelegatingFilterProxy中的doFilter方法，最终调用了initDelegate方法：

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

### 七.SpringSecurity的的Filter的工作过程

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

##### 2.讲初始化的用户名和密码放入缓存，后面认证的时候会从缓存中取

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

### 七.SpringSecurity的请求处理流程TODO

1.登录页面的返回



