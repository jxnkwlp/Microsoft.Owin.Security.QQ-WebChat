namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// 微信公众号授权配置
    /// </summary>
    public class WeixinMPAuthenticationOptions : WeixinAuthenticationOptions
    {
        /// <summary>
        /// 用来获取进入页面的用户的openid的
        /// </summary>
        public const string SCOPE_BASE = "snsapi_base";
        /// <summary>
        /// 用来获取用户的基本信息的
        /// </summary>
        public const string SCOPE_USER_INFO = "snsapi_userinfo";
        /// <summary>
        /// 授权模式：
        /// <see cref="WeixinMPAuthenticationOptions.SCOPE_BASE"/>、
        /// <see cref="WeixinMPAuthenticationOptions.SCOPE_USER_INFO"/>(默认值）
        /// 详细请参考：https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140842&token=&lang=zh_CN
        /// </summary>
        public new string Scope { set; get; } = SCOPE_USER_INFO;
    }
}
