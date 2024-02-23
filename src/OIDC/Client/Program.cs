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
        o.ClientSecret = "ClientSecretClientSecretClientSecretClientSecret";

        o.UsePkce = true;
        o.SaveTokens = true;

        o.CallbackPath = "/oidc/callback";
        o.Authority = "http://localhost:5021";
        o.ResponseType = OpenIdConnectResponseType.Code;

        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.Scope.Add("scope1");
        o.Scope.Add("offline_access");

        //o.ProtocolValidator = new OpenIdConnectProtocolValidator
        //{
        //    RequireNonce = false
        //};

        o.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ClientSecretClientSecretClientSecretClientSecret")),
            ValidateIssuerSigningKey=true,
            ValidIssuer= "avd.oauth",
            ValidateAudience=false,
            ValidateLifetime=false,
        };

        o.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
        {
            OnTokenValidated = ctx =>
            {
                return Task.CompletedTask;
            }
            //OnTokenResponseReceived =  ctx =>
            //{
            //    if (ctx.TokenEndpointResponse.AccessToken != null)
            //        ctx.Response.Cookies.Append("access_token", ctx.TokenEndpointResponse.AccessToken);
            //    if (ctx.TokenEndpointResponse.RefreshToken != null)
            //        ctx.Response.Cookies.Append("refresh_token", ctx.TokenEndpointResponse.RefreshToken);
            //    if (ctx.TokenEndpointResponse.IdToken != null)
            //        ctx.Response.Cookies.Append("id_token", ctx.TokenEndpointResponse.IdToken);

            //    return Task.CompletedTask;
            //},
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
