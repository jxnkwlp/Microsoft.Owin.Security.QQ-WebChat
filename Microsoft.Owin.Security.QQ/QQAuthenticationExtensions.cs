using System;
using Microsoft.Owin.Security.QQ;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="QQAuthenticationMiddleware"/>
    /// </summary>
    public static class QQAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using QQ
        /// </summary>
        public static IAppBuilder UseQQAuthentication(this IAppBuilder app, QQAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(QQAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using QQ
        /// </summary>
        public static IAppBuilder UseQQAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return UseQQAuthentication(app, new QQAuthenticationOptions() { AppId = appId, AppSecret = appSecret });
        }
    }
}