# Microsoft.Owin.Security Extensions

QQ and Webchat extensions for Microsoft.Owin.Security

## Get Started

- Webchat

``` csharp
    // config 
    app.UseWeixinAuthentication("[you appId]", "[you app Secret]");

    // get external login info 
    var weixinInfo = await AuthenticationManager.GetExternalWeixinLoginInfoAsync(); 
```

- Webchat MP

``` csharp
    // mp config 
    app.UseWeixinAuthentication(new WeixinMPAuthenticationOptions{
        AppId = "[you appId]", 
        AppSecret = "[you app Secret]"
    });

    // get external login info 
    var weixinInfo = await AuthenticationManager.GetExternalWeixinLoginInfoAsync(); 
```

- QQ

``` csharp
    // config 
    app.UseQQAuthentication("[you appId]", "[you app Secret]");

    // get external login info 
    var qqInfo = await AuthenticationManager.GetExternalQQLoginInfoAsync();    
```   

 

# Microsoft.Owin.Security 扩展

QQ 和微信 Owin 扩展

## 使用方法

- 微信

``` csharp
    // 配置 
    app.UseWeixinAuthentication("[you appId]", "[you app Secret]");  

    // 获取微信登录者信息
    var weixinInfo = await AuthenticationManager.GetExternalWeixinLoginInfoAsync();   
    
```

- 微信公众号

``` csharp
    // 配置 
    app.UseWeixinAuthentication(new WeixinMPAuthenticationOptions{
        AppId = "[you appId]", 
        AppSecret = "[you app Secret]"
    });  

    // 获取微信登录者信息
    var weixinInfo = await AuthenticationManager.GetExternalWeixinLoginInfoAsync();   
    
```

- QQ

``` csharp
    // 配置 
    app.UseQQAuthentication("[you appId]", "[you app Secret]");  

    // 获取QQ登录者信息
    var qqInfo = await AuthenticationManager.GetExternalQQLoginInfoAsync();    
```
