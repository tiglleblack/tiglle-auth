#### 1.JWT 的三个部分

- Header（头部）
- Payload（负载）
- Signature（签名）

写成一行：

```
Header.Payload.Signature
```

#### 2.各个组成部分

###### 1.Header（头部）

JSON 格式的元数据，定义了生成签名的算法以及 `Token` 的类型

```
{
  "alg": "HS256", //Algorithm）：签名算法，比如 HS256
  "typ": "JWT" //（Type）：令牌类型，也就是 JWT
}
```

包含的签名算法

| JWS   | 算法名称 | 描述                               |
| ----- | -------- | ---------------------------------- |
| HS256 | HMAC256  | HMAC with SHA-256                  |
| HS384 | HMAC384  | HMAC with SHA-384                  |
| HS512 | HMAC512  | HMAC with SHA-512                  |
| RS256 | RSA256   | RSASSA-PKCS1-v1_5 with SHA-256     |
| RS384 | RSA384   | RSASSA-PKCS1-v1_5 with SHA-384     |
| RS512 | RSA512   | RSASSA-PKCS1-v1_5 with SHA-512     |
| ES256 | ECDSA256 | ECDSA with curve P-256 and SHA-256 |
| ES384 | ECDSA384 | ECDSA with curve P-384 and SHA-384 |
| ES512 | ECDSA512 | ECDSA with curve P-521 and SHA-512 |

###### 2.Payload（负载）

JSON 格式的，用来存放实际需要传递的数据，可自定义字段，也可使用官方规定的7个字段

```
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

官方规定的字段

- iss (issuer)：签发人
- exp (expiration time)：过期时间
- sub (subject)：主题
- aud (audience)：受众
- nbf (Not Before)：生效时间
- iat (Issued At)：签发时间
- jti (JWT ID)：编号

###### 3.Signature（签名）

服务器通过 Payload、Header 和一个密钥(Secret)使用 Header 里面指定的签名算法生成Signature

签名的计算公式如下：

```plain
Signature=HMACSHA256(
					base64UrlEncode(header) + "." +base64UrlEncode(payload),
					secret
					)
```

#### 3.最终的token的值

```javascript
base64UrlEncode(header).
						base64UrlEncode(payload).
												 HMACSHA256(
															base64UrlEncode(header) + "." +base64UrlEncode(payload),
                                                            secret
                                                  )
```