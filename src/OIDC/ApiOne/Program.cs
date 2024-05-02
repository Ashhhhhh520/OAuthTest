using ApiOne;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorization();

// api ��Ŀͨ��Authority���ã���DiscoveryEndpoint��ȡ���ã�����token��֤��Կ��api��������֤token�� Ȩ�ޣ�scope��
// ǰ��˷���ϵͳ��ǰ�����д���refresh token 1����ʱˢ��token 2��401ʱ��ˢ��token
// ���apiֻ����server����֤

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
            OnMessageReceived =  ctx =>
            {
                // ��Authorize �� Cookies �� Url 3������֮һ��ȡaccess token
                ctx.Token = ctx.HttpContext.Request.Cookies["access_token"];
                return Task.CompletedTask;
            },
            OnTokenValidated =  ctx =>
            {
                // ��֤ scope �� ���� IdentityServer4 �� AddIdentityServerAuthencation �� ApiName 
                if ((ctx.Principal?.Identity?.IsAuthenticated ?? false))
                {
                    var scope = ctx.Principal.Claims.FirstOrDefault(a => a.Type == "scope")?.Value;
                    if (!(scope?.Contains("scope1") ?? false))
                        ctx.Fail(new Exception ("scope is invalid"));
                }
                else
                    ctx.Success();
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddSingleton<TestModel>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", (HttpContext context) =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    context.Response.Cookies.Append("six", Guid.NewGuid().ToString());
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi()
.RequireAuthorization()
;


app.UseAuthentication();
app.UseAuthorization();


app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
