using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// Configuration options for <see cref="WeixinAuthenticationMiddleware"/>
    /// </summary>
    public class WeixinAuthenticationOptions : AuthenticationOptions
    {
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public string Caption
        {
            get
            {
                return base.Description.Caption;
            }
            set
            {
                base.Description.Caption = value;
            }
        }

        public TimeSpan BackchannelTimeout { get; set; }

        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public IList<string> Scope { get; private set; }

        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IWeixinAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// 应用唯一标识，在微信开放平台提交应用审核通过后获得
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// 应用密钥 AppSecret ，在微信开放平台提交应用审核通过后获得
        /// </summary>
        public string AppSecret { get; set; }
        /// <summary>
        /// 微信服务器主机
        /// 详细请参考：https://mp.weixin.qq.com/wiki?id=mp1465199793_BqlKA&t=0.2918104504400387
        /// </summary>
        public string ApiHost { set; get; }

        public WeixinAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            this.CallbackPath = new PathString("/signin-weixin");
            AuthenticationMode = AuthenticationMode.Passive;

            Scope = new List<string>() { "snsapi_login" };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
    }
}