#### 一：初始项目

​    不添加spring-boot-starter-security的时候，访问控制器：http://localhost:8080/hello，可以随便访问

#### 二：添加SpringSecurity依赖

######     1.添加spring-boot-starter-security之后，什么都不做，启动的时候，控制台提示：

```shell
Using generated security password: 3ae5a6fb-c108-403c-ace2-63273408c5b3

This generated password is for development use only. Your security configuration must be updated before running your application in production.
```

###### 2.再次访问控制器：http://localhost:8080/hello，出现登录页面，使用账密：user,1029d33d-f87f-412d-bb4f-0da8ebaca8a8登录后成功访问

#### 三.
