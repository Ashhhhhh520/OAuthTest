using ApiOne;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorization();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.RequireHttpsMetadata = false;
        o.Authority = "http://localhost:5021";
        o.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
        };
        o.Events = new JwtBearerEvents
        {
            OnMessageReceived =  ctx =>
            {
                ctx.Token = ctx.HttpContext.Request.Cookies["access_token"];
                return Task.CompletedTask;
            },
            OnTokenValidated =  ctx =>
            {
                // 验证 scope ， 类似 IdentityServer4 的 AddIdentityServerAuthencation 的 ApiName 
                if ((ctx.Principal?.Identity?.IsAuthenticated ?? false))
                {
                    var scope = ctx.Principal.Claims.FirstOrDefault(a => a.Type == "scope")?.Value;
                    if (!(scope?.Contains("scope1") ?? false))
                        ctx.Fail(new Exception ("scope is invalid"));
                }
                else
                    ctx.Success();
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = ctx =>
            {
                // SecurityTokenExpiredException
                var ifexpired = ctx.Exception is SecurityTokenExpiredException;
                if(ifexpired)
                {

                    var identity = new ClaimsIdentity
                    {
                        
                    };

                    ctx.Principal = new System.Security.Claims.ClaimsPrincipal(identity);
                    ctx.Success();
                }
                

                return Task.CompletedTask;
            },
            OnForbidden = ctx =>
            {

                return Task.CompletedTask;
            },
            OnChallenge = ctx =>
            {

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
