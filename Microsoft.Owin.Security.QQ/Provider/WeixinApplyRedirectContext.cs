using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint
    /// </summary>
    public class WeixinApplyRedirectContext : BaseContext<WeixinAuthenticationOptions>
    {
        public WeixinApplyRedirectContext(IOwinContext context, WeixinAuthenticationOptions options,
            AuthenticationProperties properties, string redirectUri) : base(context, options)
        {
            RedirectUri = redirectUri;
            Properties = properties;
        }

        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Gets the authenticaiton properties of the challenge
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }
    }
}