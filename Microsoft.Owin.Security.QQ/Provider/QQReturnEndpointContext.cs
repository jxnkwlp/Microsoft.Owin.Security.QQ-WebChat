using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.QQ
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class QQReturnEndpointContext : ReturnEndpointContext
    {
        public QQReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
        {
        }
    }
}