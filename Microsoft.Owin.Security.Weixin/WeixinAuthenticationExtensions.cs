using System;
using Microsoft.Owin.Security.Weixin;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="WeixinAuthenticationMiddleware"/>
    /// </summary>
    public static class WeixinAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Weixin
        /// </summary>
        public static IAppBuilder UseWeixinAuthentication(this IAppBuilder app, WeixinAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(WeixinAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Weixin
        /// </summary>
        public static IAppBuilder UseWeixinAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return UseWeixinAuthentication(app, new WeixinAuthenticationOptions() { AppId = appId, AppSecret = appSecret });
        }
    }
}