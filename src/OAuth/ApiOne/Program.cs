using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

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
        o.Authority = "http://localhost:5231";
        o.Audience = "client";
        //o.TokenValidationParameters = new TokenValidationParameters
        //{
        //    ValidateActor = false,
        //    ValidateAudience = false,
        //    ValidateIssuer = false,
        //    ValidateLifetime = true,
        //    ClockSkew = new TimeSpan(0, 0, 5),
        //    ValidateIssuerSigningKey = true,
        //    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("clientclientclientclientclientclient")),
        //};
        o.Events = new JwtBearerEvents
        {
            OnMessageReceived =async ctx =>
            {
                ctx.Token = ctx.HttpContext.Request.Cookies["access_token"];
            },
        };
    });

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

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.RequireAuthorization()
.WithOpenApi();

app.UseAuthentication();
app.UseAuthorization();

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
