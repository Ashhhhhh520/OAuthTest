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

/// ϵͳ����token��˽Կ
builder.Services.AddSingleton<DevKeys>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseStaticFiles();

app.UseRouting();

/// oidc configuration doc api���������ĵ��е�required ��Ŀ�����  https://openid.net/specs/openid-connect-discovery-1_0.html
app.MapGet(".well-known/openid-configuration", DiscoveryEndpoint.GetDiscoveryDoc);

/// ��ǰserver�ĵ�¼�ӿڣ� ͨ��cookies ��֤server�Ƿ��¼������ת��authorize �ӿ���OAuth2.0����
app.MapGet("/oauth/authorize", AuthorizeEndpoint.Authorize).RequireAuthorization();

/// authorize�ӿڽ����󣬷���client�ε� callback path �� �ٴ�token�ӿڻ�ȡ����token�� ����Ҫ��֤�����code��verifycode�� client secret֮�������
app.MapPost("/oauth/token", TokenEndpoint.GetToken);

/// id token �������ȡ�û�����
app.MapGet("/oauth/userinfo", UserInfoEnpoint.GetUserInfo);

/// ������������token�Ĺ�Կ��Ϣ
app.MapGet("/oauth/jwks", JwkEnpoint.GetJwks);

app.UseMiddleware<ValidOAuthParameterMiddleware>();

app.UseAuthentication();
app.UseAuthorization();


app.MapControllers();

app.Run();
