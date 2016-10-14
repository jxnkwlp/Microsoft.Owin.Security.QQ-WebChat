using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Weixin;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security
{
    public static class AuthenticationManagerExtensions
    {
        public static async Task<Dictionary<string, string>> GetExternalWeixinLoginInfoAsync(this IAuthenticationManager manager)
        {
            return await GetExternalWeixinLoginInfoAsync(manager, "ExternalCookie");
        }

        public static async Task<Dictionary<string, string>> GetExternalWeixinLoginInfoAsync(this IAuthenticationManager manager, string externalAuthenticationType)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }

            var result = await manager.AuthenticateAsync(externalAuthenticationType);

            if (result != null && result.Identity != null && result.Identity.FindFirst(Constants.WeixinClaimType) != null)
            {
                var value = result.Identity.FindFirst(Constants.WeixinClaimType).Value;

                if (!string.IsNullOrEmpty(value))
                {
                    var jObject = JObject.Parse(value);

                    Dictionary<string, string> dict = new Dictionary<string, string>();

                    foreach (var item in jObject)
                    {
                        dict[item.Key] = item.Value == null ? null : item.Value.ToString();
                    }

                    return await Task.FromResult(dict);
                }
            }
            return null;
        }
    }
}