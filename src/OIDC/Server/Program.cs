using Server.Endpoints;
using Server.Middlewares;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();
builder.Services.AddControllersWithViews();
// Add services to the container.
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie", o =>
    {
        o.LoginPath = "/login";
    });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseStaticFiles();

app.UseRouting();

app.MapGet(".well-known/openid-configuration", DiscoveryEndpoint.GetDiscoveryDoc);

app.MapGet("/oauth/authorize", AuthorizeEndpoint.Authorize).RequireAuthorization();
//app.MapPost("/oauth/authorize", AuthorizeEndpoint.SubmitAuthorize).RequireAuthorization();

app.MapPost("/oauth/token", TokenEndpoint.GetToken);

app.MapPost("/oauth/userinfo", UserInfoEnpoint.GetUserInfo).RequireAuthorization();

app.UseMiddleware<ValidOAuthParameterMiddleware>();

app.UseAuthentication();
app.UseAuthorization();


app.MapControllers();

app.Run();
