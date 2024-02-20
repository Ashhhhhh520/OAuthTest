using Microsoft.AspNetCore.Authentication;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddAuthentication("custom")
    .AddCookie("cookie")
    .AddOAuth("custom", o =>
    {
        o.SignInScheme = "cookie";

        o.ClientId = "client";
        o.ClientSecret= "client";

        o.AuthorizationEndpoint = "https://localhost:7259/oauth/authorize";
        o.TokenEndpoint = "https://localhost:7259/oauth/token";
        o.CallbackPath = "/oauth/callback";

        // 这个作用是?
        o.Scope.Add("scope1");
        o.Scope.Add("scope2");
        o.Scope.Add("scope3");
        o.Scope.Add("scope4");

        o.SaveTokens = true;

        o.ClaimActions.MapJsonKey("custom_claim", "custom_claim");
        o.ClaimActions.MapJsonKey("scope", "scope");

        o.UsePkce = true;
        o.Events.OnCreatingTicket = async ctx =>
        {
            var playload64 = ctx.AccessToken!.Split('.')[1];
            var json = JsonDocument.Parse(Base64UrlTextEncoder.Decode(playload64));
            ctx.RunClaimActions(json.RootElement);
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
