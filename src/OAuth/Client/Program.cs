using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddAuthentication("custom")
    .AddCookie("cookie")
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o =>
    {
        o.Authority = "http://localhost:5231";
        o.RequireHttpsMetadata = false;
        o.
        o.Events = new JwtBearerEvents
        {
            OnMessageReceived = async ctx =>
            {
                var iftoken = ctx.Request.Cookies.TryGetValue("access_token", out var token);
                if (iftoken)
                    ctx.Token = token;
            }
        };
    })
    .AddOAuth("custom", o =>
    {
        o.SignInScheme = "cookie";

        o.ClientId = "client";
        o.ClientSecret = "client";

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
    //.AddOpenIdConnect("oidc", o =>
    //{
    //    o.SignInScheme = "cookie";

    //    o.ClientId = "client";
    //    o.ClientSecret = "client";

    //    o.Scope.Add("scope1");
    //    o.Scope.Add("scope2");
    //    o.Scope.Add("scope3");
    //    o.Scope.Add("scope4");

    //    o.UsePkce = true;
    //    o.SaveTokens = true;

    //})
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
