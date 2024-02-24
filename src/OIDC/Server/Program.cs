using Server;
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

/// 系统生成token的私钥
builder.Services.AddSingleton<DevKeys>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseStaticFiles();

app.UseRouting();

/// oidc configuration doc api，将链接文档中的required 项目输出，  https://openid.net/specs/openid-connect-discovery-1_0.html
app.MapGet(".well-known/openid-configuration", DiscoveryEndpoint.GetDiscoveryDoc);

/// 当前server的登录接口， 通过cookies 验证server是否登录，再跳转回authorize 接口走OAuth2.0流程
app.MapGet("/oauth/authorize", AuthorizeEndpoint.Authorize).RequireAuthorization();

/// authorize接口结束后，返回client段的 callback path ， 再从token接口获取各个token， 这里要验证请求的code，verifycode， client secret之类的数据
app.MapPost("/oauth/token", TokenEndpoint.GetToken);

/// id token 来这里获取用户数据
app.MapGet("/oauth/userinfo", UserInfoEnpoint.GetUserInfo);

/// 返回用于生成token的公钥信息
app.MapGet("/oauth/jwks", JwkEnpoint.GetJwks);

app.UseMiddleware<ValidOAuthParameterMiddleware>();

app.UseAuthentication();
app.UseAuthorization();


app.MapControllers();

app.Run();
