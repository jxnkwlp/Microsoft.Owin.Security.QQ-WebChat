using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// Specifies callback methods which the <see cref="WeixinAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IWeixinAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever succesfully authenticates a user
        /// </summary>
        Task Authenticated(WeixinAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        Task ReturnEndpoint(WeixinReturnEndpointContext context);

        ///// <summary>
        ///// Called when a Challenge causes a redirect to authorize endpoint in the Microsoft middleware
        ///// </summary>
        //void ApplyRedirect(WeixinApplyRedirectContext context);
    }
}