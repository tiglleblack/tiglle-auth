#            SpringSecurity源码解析

### 一.默认Spring Filters的初始化流程

springboot启动时，会进行自动装配，新版会扫描classpath下的文件：
classpath:/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports

然后又加载此文件中的所有自动装配类，其中包含：

org.springframework.boot.autoconfigure.security.servlet.SerurityAutoConfigration
