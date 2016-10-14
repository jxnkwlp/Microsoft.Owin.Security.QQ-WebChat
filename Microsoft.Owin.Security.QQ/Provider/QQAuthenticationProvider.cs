using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.QQ
{
    /// <summary>
    /// Default <see cref="IQQAuthenticationProvider"/> implementation.
    /// </summary>
    public class QQAuthenticationProvider : IQQAuthenticationProvider
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<QQAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<QQReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        ///// <summary>
        ///// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        ///// </summary>
        public Action<QQApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        ///
        /// </summary>
        public QQAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint
        /// </summary>
        public void ApplyRedirect(QQApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }

        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        public Task Authenticated(QQAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        public Task ReturnEndpoint(QQReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}