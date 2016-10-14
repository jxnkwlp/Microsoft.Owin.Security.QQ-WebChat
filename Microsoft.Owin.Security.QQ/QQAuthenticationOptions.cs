using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.Owin.Security.QQ
{
    /// <summary>
    /// Configuration options for <see cref="QQAuthenticationMiddleware"/>
    /// </summary>
    public class QQAuthenticationOptions : AuthenticationOptions
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

        /// <summary>
        /// 请求用户授权时向用户显示的可进行授权的列表。
        /// </summary>
        public IList<string> Scope { get; private set; }

        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IQQAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// 申请QQ登录成功后，分配给应用的appid。
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// 申请QQ登录成功后，分配给网站的appkey。
        /// </summary>
        public string AppSecret { get; set; }

        public QQAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            this.CallbackPath = new PathString("/signin-qq");
            AuthenticationMode = AuthenticationMode.Passive;

            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
    }
}