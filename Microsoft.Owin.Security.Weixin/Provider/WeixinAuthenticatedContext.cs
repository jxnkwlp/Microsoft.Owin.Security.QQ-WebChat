using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class WeixinAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the access token provided by the authenication service
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>
        /// 普通用户的标识，对当前开发者帐号唯一
        /// </summary>
        public string OpenId { get; set; }

        /// <summary>
        /// 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
        /// </summary>
        public string UnionId { get; set; }

        public string Nickame { get; set; }
        public string Sex { get; set; }
        public string Province { get; set; }
        public string City { get; set; }
        public string Country { get; set; }
        public string HeadimgUrl { get; set; }
        public string Privilege { get; set; }
        /// <summary>
        /// 当UnionId不为空时，用户Id为<see cref="UnionId"/>，否则为 <see cref="OpenId"/>
        /// </summary>
        public string UserId { private set; get; }

        public WeixinAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expires) : base(context)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            this.User = user;
            this.AccessToken = accessToken;

            int num;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out num))
            {
                this.ExpiresIn = new TimeSpan?(TimeSpan.FromSeconds((double)num));
            }

            this.OpenId = GetSafeValue("openid", user);
            this.Nickame = GetSafeValue("nickname", user);
            this.Sex = GetSafeValue("sex", user);
            this.Province = GetSafeValue("province", user);
            this.City = GetSafeValue("city", user);
            this.Country = GetSafeValue("country", user);
            this.HeadimgUrl = GetSafeValue("headimgurl", user);
            this.Privilege = GetSafeValue("privilege", user);
            this.UnionId = GetSafeValue("unionid", user);

            if (string.IsNullOrWhiteSpace(this.UnionId))
            {
                this.UserId = OpenId;
            }
            else
            {
                this.UserId = UnionId;
            }

            if (string.IsNullOrWhiteSpace(this.UserId))
            {
                throw new ArgumentException("user not found. ");
            }
        }

        private static string GetSafeValue(string name, IDictionary<string, JToken> dictionary)
        {
            if (!dictionary.ContainsKey(name))
            {
                return null;
            }
            return dictionary[name].ToString();
        }
    }
}