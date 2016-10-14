using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// Default <see cref="IWeixinAuthenticationProvider"/> implementation.
    /// </summary>
    public class WeixinAuthenticationProvider : IWeixinAuthenticationProvider
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<WeixinAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<WeixinReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        ///// <summary>
        ///// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        ///// </summary>
        //public Action<WeixinApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        ///
        /// </summary>
        public WeixinAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            // OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        ///// <summary>
        ///// Called when a Challenge causes a redirect to authorize endpoint
        ///// </summary>
        //public void ApplyRedirect(WeixinApplyRedirectContext context)
        //{
        //    OnApplyRedirect(context);
        //}

        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        public Task Authenticated(WeixinAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        public Task ReturnEndpoint(WeixinReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}