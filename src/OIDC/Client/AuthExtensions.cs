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
                // 仅发送到idp验证用， 不用于生成token
                o.ClientSecret = "ClientSecretClientSecretClientSecretClientSecret";

                o.UsePkce = true;
                o.SaveTokens = true;

                o.CallbackPath = "/oidc/callback";
                o.Authority = "http://localhost:5021";
                o.ClaimsIssuer = "ash.oauth";
                o.ResponseType = OpenIdConnectResponseType.Code;
                //o.GetClaimsFromUserInfoEndpoint = true;

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
                        //if (ctx.TokenEndpointResponse.AccessToken != null)
                        //{
                        //    ctx.Response.Cookies.Append("access_token", ctx.TokenEndpointResponse.AccessToken);
                        //}
                        //if (ctx.TokenEndpointResponse.IdToken != null)
                        //{
                        //    ctx.Response.Cookies.Append("id_token", ctx.TokenEndpointResponse.IdToken);
                        //}
                        //if (ctx.TokenEndpointResponse.RefreshToken != null)
                        //{
                        //    ctx.Response.Cookies.Append("refresh_token", ctx.TokenEndpointResponse.RefreshToken);
                        //}
                        return Task.CompletedTask;
                    },
                };
            });
        }

        public static void AddJwtAuth(this IServiceCollection services)
        {
            // api 项目通过Authority配置，从DiscoveryEndpoint获取配置，包括token验证公钥，api端自行验证token， 权限，scope等
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(o =>
                {
                    o.RequireHttpsMetadata = false;
                    o.Authority = "http://localhost:5021";
                    o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                    };
                    o.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = ctx =>
                        {
                            ctx.Token = ctx.HttpContext.Request.Cookies["access_token"];
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = ctx =>
                        {
                            if(!ctx.HttpContext?.User?.Identity?.IsAuthenticated ?? false)
                            {
                                ctx.Fail(new LoginException());
                                return Task.CompletedTask;
                            }

                            // 验证 scope ， 类似 IdentityServer4 的 AddIdentityServerAuthencation 的 ApiName 
                            if ((ctx.Principal?.Identity?.IsAuthenticated ?? false))
                            {
                                var scope = ctx.Principal.Claims.FirstOrDefault(a => a.Type == "scope")?.Value;
                                if (!(scope?.Contains("scope1") ?? false))
                                    ctx.Fail(new Exception("scope is invalid"));
                            }
                            else
                                ctx.Success();
                            return Task.CompletedTask;
                        },
                        OnAuthenticationFailed = ctx =>
                        {
                            ctx.Response.Redirect("http://localhost:5021/oauth/authorize");
                            return Task.CompletedTask;
                            //if(ctx.Exception is LoginException)
                            //{
                            //    ctx.Response.Redirect("http://localhost:5021/oauth/authorize");
                            //    return Task.CompletedTask;
                            //}

                            //var ifexpired = ctx.Exception is SecurityTokenExpiredException;
                            //if (ifexpired)
                            //{
                            //    // 标记token 过期, 让客户端去刷新token
                            //    ctx.Response.Headers.TryAdd("Token-Expired", "true");
                            //}
                            //return Task.CompletedTask;
                        }
                    };
                });
        }
    }
}
