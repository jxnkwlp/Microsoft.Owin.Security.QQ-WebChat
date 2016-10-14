using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class WeixinReturnEndpointContext : ReturnEndpointContext
    {
        public WeixinReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
        {
        }
    }
}