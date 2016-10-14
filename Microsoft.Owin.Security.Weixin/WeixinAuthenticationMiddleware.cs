using System;
using System.Net.Http;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// OWIN middleware for authenticating users using the weixin service
    /// </summary>
    public class WeixinAuthenticationMiddleware : AuthenticationMiddleware<WeixinAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public WeixinAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WeixinAuthenticationOptions options) : base(next, options)
        {
            if (string.IsNullOrEmpty(options.AppId))
                throw new ArgumentNullException("AppId Must Be Provided.");
            if (string.IsNullOrEmpty(options.AppSecret))
                throw new ArgumentNullException("AppSecret Must Be Provided.");

            _logger = app.CreateLogger<WeixinAuthenticationMiddleware>();

            if (Options.Provider == null)
            {
                Options.Provider = new WeixinAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtecter = app.CreateDataProtector(
                    typeof(WeixinAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }
            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        protected override AuthenticationHandler<WeixinAuthenticationOptions> CreateHandler()
        {
            return new WeixinAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(WeixinAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException();
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}