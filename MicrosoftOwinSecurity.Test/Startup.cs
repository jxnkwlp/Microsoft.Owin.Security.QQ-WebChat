using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MicrosoftOwinSecurity.Test.Startup))]
namespace MicrosoftOwinSecurity.Test
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
