using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.QQ
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class QQAuthenticatedContext : BaseContext
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

        public string OpenId { get; set; }

        public string Nickame { get; set; }
        public string FigureUrl { get; set; }
        public string FigureUrl_1 { get; set; }
        public string FigureUrl_2 { get; set; }
        public string FigureUrl_QQ_1 { get; set; }
        public string FigureUrl_QQ_2 { get; set; }
        public string Gender { get; set; }

        public string Is_Yellow_Vip { get; set; }
        public string IsVip { get; set; }
        public string Yellow_Vip_Level { get; set; }
        public string Level { get; set; }
        public string Is_Yellow_Year_Vip { get; set; }

        public QQAuthenticatedContext(IOwinContext context, string openId, JObject userInfo, string accessToken, string refreshToken, string expires) : base(context)
        {
            if (string.IsNullOrEmpty(openId))
            {
                throw new ArgumentNullException("openId");
            }

            if (userInfo == null)
            {
                throw new ArgumentNullException("user");
            }
            this.User = userInfo;
            this.AccessToken = accessToken;

            int num;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out num))
            {
                this.ExpiresIn = new TimeSpan?(TimeSpan.FromSeconds((double)num));
            }

            this.OpenId = openId;

            this.Nickame = GetSafeValue("nickname", userInfo);
            this.FigureUrl = GetSafeValue("figureurl", userInfo);
            this.FigureUrl_1 = GetSafeValue("figureurl_1", userInfo);
            this.FigureUrl_2 = GetSafeValue("figureurl_2", userInfo);
            this.FigureUrl_QQ_1 = GetSafeValue("figureurl_qq_1", userInfo);
            this.FigureUrl_QQ_2 = GetSafeValue("figureurl_qq_2", userInfo);
            this.Gender = GetSafeValue("gender", userInfo);
            this.Is_Yellow_Vip = GetSafeValue("is_yellow_vip", userInfo);
            this.IsVip = GetSafeValue("vip", userInfo);
            this.Yellow_Vip_Level = GetSafeValue("yellow_vip_level", userInfo);
            this.Level = GetSafeValue("level", userInfo);
            this.Is_Yellow_Year_Vip = GetSafeValue("is_yellow_year_vip", userInfo);
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