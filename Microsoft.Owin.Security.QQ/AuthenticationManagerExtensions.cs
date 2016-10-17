using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Owin.Security.QQ;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security
{
    public static class AuthenticationManagerExtensions
    {
        /// <summary>
        ///   Get an dictionary from external login info
        /// </summary>
        /// <param name="manager"></param>
        /// <returns>All keys: ret,msg,is_lost,nickname,gender,province,city,year,figureurl,figureurl_1,figureurl_2,figureurl_qq_1,figureurl_qq_2,is_yellow_vip,vip,yellow_vip_level,level,is_yellow_year_vip</returns>
        public static async Task<Dictionary<string, string>> GetExternalQQLoginInfoAsync(this IAuthenticationManager manager)
        {
            return await GetExternalQQLoginInfoAsync(manager, "ExternalCookie");
        }

        public static async Task<Dictionary<string, string>> GetExternalQQLoginInfoAsync(this IAuthenticationManager manager, string externalAuthenticationType)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }

            var result = await manager.AuthenticateAsync(externalAuthenticationType);

            if (result != null && result.Identity != null && result.Identity.FindFirst(Constants.QQClaimType) != null)
            {
                var value = result.Identity.FindFirst(Constants.QQClaimType).Value;

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