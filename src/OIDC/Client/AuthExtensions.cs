using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Client
{
    public static class AuthExtensions
    {
        public static void AddOpenIDAuth(this IServiceCollection services)
        {
            // mvc端直接用cookies做系统认证
            // 前后端分离系统，前端自行处理refresh token 1：定时刷新token 2：401时再刷新token
            services.AddAuthentication("oidc")
            .AddCookie("cookie", o =>
            {
                o.SlidingExpiration = true;
                o.ExpireTimeSpan = TimeSpan.FromMinutes(10);
            })
            .AddOpenIdConnect("oidc", o =>
            {
                o.SignInScheme = "cookie";
                o.RequireHttpsMetadata = false;
                o.ClientId = "client";
                // 仅发送到idp验证用
                o.ClientSecret = "ClientSecretClientSecretClientSecretClientSecret";

                o.UsePkce = true;
                o.SaveTokens = true;

                o.CallbackPath = "/oidc/callback";
                o.Authority = "http://localhost:5021";
                o.ClaimsIssuer = "ash.oauth";

                // Response Type 包含 code，client端需要生成code_challenge并发送到server，server端加密code_challenge&其他数据，生成code_verifier然后返回给client端，
                // client端请求Token流程会携带code_challenge和code_verifier参数，server端需要验证两个参数
                // code ResponseType有code_challenge，code_challenge
                o.ResponseType = OpenIdConnectResponseType.IdTokenToken;
                //o.GetClaimsFromUserInfoEndpoint = true;

                //o.ResponseMode = OpenIdConnectResponseMode.Query;

                // 设置需要验证的 openid connect 协议数据
                // RequireNonce=false ， 就不会生成nonce发送到server端
                //o.ProtocolValidator = new OpenIdConnectProtocolValidator { RequireNonce = false,RequireSub=true };

                o.Scope.Add("openid");
                o.Scope.Add("profile");
                o.Scope.Add("scope1");
                o.Scope.Add("offline_access");

                o.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
                {
                    OnMessageReceived = ctx =>
                    {
                        return Task.CompletedTask;
                    },
                    OnTokenResponseReceived = ctx =>
                    {
                        return Task.CompletedTask;
                    },
                };
            });
        }
    }
}
