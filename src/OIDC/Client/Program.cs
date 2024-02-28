using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();


builder.Services.AddAuthentication("oidc")
    .AddCookie("cookie")
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
            OnTokenResponseReceived = ctx =>
            {
                ctx.Response.Headers["Authorize"] = ctx.TokenEndpointResponse.AccessToken;
                ctx.Response.Headers["Refresh_Token"] = ctx.TokenEndpointResponse.RefreshToken;
                //if (ctx.TokenEndpointResponse.AccessToken != null)
                //    ctx.Response.Cookies.Append("access_token", ctx.TokenEndpointResponse.AccessToken);
                //if (ctx.TokenEndpointResponse.RefreshToken != null)
                //    ctx.Response.Cookies.Append("refresh_token", ctx.TokenEndpointResponse.RefreshToken);
                //if (ctx.TokenEndpointResponse.IdToken != null)
                //    ctx.Response.Cookies.Append("id_token", ctx.TokenEndpointResponse.IdToken);
                return Task.CompletedTask;
            },
        };
    })
    ;

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();
IdentityModelEventSource.ShowPII = true;
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
