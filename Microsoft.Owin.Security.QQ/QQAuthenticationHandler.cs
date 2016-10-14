using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.QQ
{
    //     +----------+
    //     | resource |
    //     |   owner  |
    //     |          |
    //     +----------+
    //          ^
    //          |
    //         (B)
    //     +----|-----+          Client Identifier      +---------------+
    //     |         -+----(A)-- & Redirection URI ---->|               |
    //     |  User-   |                                 | Authorization |
    //     |  Agent  -+----(B)-- User authenticates --->|     Server    |
    //     |          |                                 |               |
    //     |         -+----(C)-- Authorization Code ---<|               |
    //     +-|----|---+                                 +---------------+
    //       |    |                                         ^      v
    //      (A)  (C)                                        |      |
    //       |    |                                         |      |
    //       ^    v                                         |      |
    //     +---------+                                      |      |
    //     |         |>---(D)-- Authorization Code ---------'      |
    //     |  Client |          & Redirection URI                  |
    //     |         |                                             |
    //     |         |<---(E)----- Access Token -------------------'
    //     +---------+       (w/ Optional Refresh Token)

    /// <summary>
    ///
    /// </summary>
    internal class QQAuthenticationHandler : AuthenticationHandler<QQAuthenticationOptions>
    {
        private const string AuthorizationEndpoint = "https://graph.qq.com/oauth2.0/authorize";
        private const string TokenEndpoint = "https://graph.qq.com/oauth2.0/token";
        private const string TokenRefreshEndpoint = "https://graph.qq.com/oauth2.0/token";
        private const string UserOpenIdEndpoint = "https://graph.qq.com/oauth2.0/me";
        private const string UserInfoEndpoint = "https://graph.qq.com/user/get_user_info";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public QQAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        /// <summary>
        /// 授权处理
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                // 获取 accessToken 授权令牌
                var oauth2Token = await ObtainAccessTokenAsync(code);

                string accessToken = oauth2Token["access_token"];

                // Refresh token is only available
                // Otherwise, it is null.
                var refreshToken = oauth2Token["refresh_token"];
                var expire = oauth2Token["expires_in"];

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                // 获取用户openid
                JObject userOpenIdToken = await ObtainUserOpenIdAsync(accessToken);

                string openId = userOpenIdToken["openid"].Value<string>();

                if (string.IsNullOrEmpty(openId))
                {
                    _logger.WriteWarning("User openId was not found");
                    return new AuthenticationTicket(null, properties);
                }

                // 获取用户个人信息
                JObject userInfoToken = await ObtainUserInfoAsync(accessToken, openId);

                var context = new QQAuthenticatedContext(Context, openId, userInfoToken, accessToken, refreshToken, expire);

                context.Identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.NameIdentifier, context.OpenId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                    new Claim(ClaimTypes.Name, context.Nickame, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                    new Claim("urn:qqconnect:id", context.OpenId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                    new Claim("urn:qqconnect:name", context.Nickame, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),

                    new Claim( Constants.QQClaimType ,  userInfoToken.ToString() , "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                }, Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                context.Properties = properties;

                // 没有Email
                //if (!string.IsNullOrWhiteSpace(context.Email))
                //{
                //    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                //}

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        // Step2：通过Authorization Code获取Access Token
        private async Task<Dictionary<string, string>> ObtainAccessTokenAsync(string code)
        {
            string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;

            string currentUri = baseUri + Request.Path + Request.QueryString;

            string redirectUri = baseUri + Options.CallbackPath;

            var requestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", Options.AppId),
                    new KeyValuePair<string, string>("client_secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                };

            StringBuilder parameterBuilder = new StringBuilder();
            foreach (var item in requestParameters)
            {
                parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(item.Key), Uri.EscapeDataString(item.Value));
            }
            parameterBuilder.Length--;
            string parameterString = parameterBuilder.ToString();

            var response = await _httpClient.GetAsync(TokenEndpoint + "?" + parameterString, Request.CallCancelled);
            response.EnsureSuccessStatusCode();

            string oauthTokenResponse = await response.Content.ReadAsStringAsync();

            // access_token=786AB61C845B36CA*******&expires_in=7776000&refresh_token=37FB8813EBECA********

            var oauthTokenDict = new Dictionary<string, string>();

            var responseParams = oauthTokenResponse.Split('&');

            foreach (var parm in responseParams)
            {
                var kv = parm.Split('=');
                oauthTokenDict[kv[0]] = kv[1];
            }

            return oauthTokenDict;
        }

        //
        private async Task<JObject> ObtainUserOpenIdAsync(string accessToken)
        {
            var response = await _httpClient.GetAsync(UserOpenIdEndpoint + "?access_token=" + accessToken, Request.CallCancelled);
            response.EnsureSuccessStatusCode();

            string oauthTokenResponse = await response.Content.ReadAsStringAsync();

            // callback( {"client_id":"YOUR_APPID","openid":"YOUR_OPENID"} );\n

            oauthTokenResponse = oauthTokenResponse.Remove(0, 9);
            oauthTokenResponse = oauthTokenResponse.Remove(oauthTokenResponse.Length - 3);

            JObject oauth2Token = JObject.Parse(oauthTokenResponse);

            return oauth2Token;
        }

        private async Task<JObject> ObtainUserInfoAsync(string accessToken, string openId)
        {
            var response = await _httpClient.GetAsync(string.Format("{0}?access_token={1}&oauth_consumer_key={2}&openid={3}", UserInfoEndpoint, accessToken, Options.AppId, openId), Request.CallCancelled);
            response.EnsureSuccessStatusCode();

            string oauthTokenResponse = await response.Content.ReadAsStringAsync();

            JObject oauth2Token = JObject.Parse(oauthTokenResponse);

            return oauth2Token;
        }

        /// <summary>
        ///  执行401跳转
        /// </summary>
        /// <returns></returns>
        protected override Task ApplyResponseChallengeAsync()
        {
            // return base.ApplyResponseChallengeAsync();

            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;

                string currentUri = baseUri + Request.Path + Request.QueryString;

                string redirectUri = baseUri + Options.CallbackPath;

                AuthenticationProperties extra = challenge.Properties;
                if (string.IsNullOrEmpty(extra.RedirectUri))
                {
                    extra.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(extra);

                string scope = string.Join(",", Options.Scope);
                if (string.IsNullOrEmpty(scope))
                {
                    scope = "get_user_info";
                }

                string state = Options.StateDataFormat.Protect(extra);

                string authorizationEndpoint = string.Format(AuthorizationEndpoint + "?client_id={0}&redirect_uri={1}&response_type=code&scope={2}&state={3}",
                    Uri.EscapeDataString(Options.AppId),
                    Uri.EscapeDataString(redirectUri),
                    Uri.EscapeDataString(scope),
                    Uri.EscapeDataString(state));

                // 跳转到 授权服务器 页面
                // Context.Response.Redirect(authorizationEndpoint);

                var redirectContext = new QQApplyRedirectContext(Context, Options, extra, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            // return base.InvokeAsync();
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket model = await AuthenticateAsync();
            if (model == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new QQReturnEndpointContext(Context, model);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = model.Properties.RedirectUri;
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    context.RedirectUri = context.RedirectUri; //WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                }
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        private string GenerateRedirectUri()
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(state));
            return redirectUri;
        }
    }
}