using System.Threading.Tasks;

namespace Microsoft.Owin.Security.QQ
{
    /// <summary>
    /// Specifies callback methods which the <see cref="QQAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IQQAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        Task Authenticated(QQAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        Task ReturnEndpoint(QQReturnEndpointContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the Microsoft middleware
        /// </summary>
        void ApplyRedirect(QQApplyRedirectContext context);
    }
}