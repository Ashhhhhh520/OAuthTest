using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddAuthentication("custom")
    .AddCookie("cookie")
    // OAuth 验证也只是适合单体项目
    .AddOAuth("custom", o =>
    {
        o.SignInScheme = "cookie";

        o.ClientId = "client";
        o.ClientSecret = "ClientSecretClientSecretClientSecretClientSecretClientSecret";

        o.AuthorizationEndpoint = "http://localhost:5231/oauth/authorize";
        o.TokenEndpoint = "http://localhost:5231/oauth/token";
        o.CallbackPath = "/oauth/callback";

        o.Scope.Add("scope1");
        o.Scope.Add("scope2");
        o.Scope.Add("scope3");
        o.Scope.Add("scope4");

        //o.SaveTokens = true;

        o.UsePkce = true;
        o.Events.OnCreatingTicket = async ctx =>
        {
            if (ctx.AccessToken == null)
                return;
            var tokenreader = new JwtSecurityTokenHandler().ReadJwtToken(ctx.AccessToken);
            ctx.Identity?.AddClaims(tokenreader.Claims);
            ctx.Response.Cookies.Append("access_token", ctx.AccessToken);
        };
    })
    ;

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    //app.UseHsts();
}

//app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
