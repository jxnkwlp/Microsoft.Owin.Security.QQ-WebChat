using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.QQ
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the middleware
    /// </summary>
    public class QQApplyRedirectContext : BaseContext<QQAuthenticationOptions>
    {
        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Gets the authenticaiton properties of the challenge
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }

        public QQApplyRedirectContext(IOwinContext context, QQAuthenticationOptions options, AuthenticationProperties properties, string redirectUri) : base(context, options)
        {
            this.RedirectUri = redirectUri;
            this.Properties = Properties;
        }
    }
}