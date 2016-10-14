using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.Weixin
{
    /// <summary>
    ///
    /// </summary>
    internal class WeixinAuthenticationHandler : AuthenticationHandler<WeixinAuthenticationOptions>
    {
        private const string AuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect";
        private const string TokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";
        private const string TokenRefreshEndpoint = "https://api.weixin.qq.com/sns/oauth2/refresh_token";
        private const string UserInfoEndpoint = "https://api.weixin.qq.com/sns/userinfo";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public WeixinAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
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

                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("appid", Options.AppId),
                    new KeyValuePair<string, string>("secret", Options.AppSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };

                var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

                // 通过code获取access_token
                HttpResponseMessage response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                string oauthTokenResponse = await response.Content.ReadAsStringAsync();

                JObject oauth2Token = JObject.Parse(oauthTokenResponse);
                var accessToken = oauth2Token["access_token"].Value<string>();

                // Refresh token is only available when wl.offline_access is request.
                // Otherwise, it is null.
                var refreshToken = oauth2Token.Value<string>("refresh_token");
                var expire = oauth2Token.Value<string>("expires_in");

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                var openId = oauth2Token.Value<string>("openid");
                var scope = oauth2Token.Value<string>("scope");
                var unionId = oauth2Token.Value<string>("unionid");

                // 获取用户信息
                var userInfoResponse = await _httpClient.GetAsync(string.Format(UserInfoEndpoint + "?access_token={0}&openid={1}", Uri.EscapeDataString(accessToken), Uri.EscapeDataString(openId)), Request.CallCancelled);

                userInfoResponse.EnsureSuccessStatusCode();
                string userInfoResponseString = await userInfoResponse.Content.ReadAsStringAsync();

                JObject userInformation = JObject.Parse(userInfoResponseString);

                var context = new WeixinAuthenticatedContext(Context, userInformation, accessToken, refreshToken, expire);

                context.Identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.NameIdentifier, context.UnionId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                    new Claim(ClaimTypes.Name, context.Nickame, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                    new Claim("urn:weixinconnect:id", context.UnionId, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                    new Claim("urn:weixinconnect:name", context.Nickame, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),

                    new Claim( Constants.WeixinClaimType ,  userInformation.ToString() , "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType),
                }, Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                // 没有Email
                //if (!string.IsNullOrWhiteSpace(context.Email))
                //{
                //    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                //}

                await Options.Provider.Authenticated(context);

                context.Properties = properties;

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
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

                string state = Options.StateDataFormat.Protect(extra);

                string authorizationEndpoint = string.Format(AuthorizationEndpoint + "?appid={0}&redirect_uri={1}&response_type=code&scope={2}&state={3}#wechat_redirect",
                    Uri.EscapeDataString(Options.AppId),
                    Uri.EscapeDataString(redirectUri),
                    Uri.EscapeDataString(scope),
                    Uri.EscapeDataString(state));

                Context.Response.Redirect(authorizationEndpoint);

                // var redirectContext = new WeixinApplyRedirectContext(Context, Options, extra, authorizationEndpoint);
                //Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
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

            var context = new WeixinReturnEndpointContext(Context, model);
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