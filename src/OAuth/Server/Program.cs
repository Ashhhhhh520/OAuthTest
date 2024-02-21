using Server;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// client �����/oauth/authorize ��ȡtoken, ��api��Ҫ[Authorize], δ�ٵ�ǰServer��¼��Ҫ��ת��loginҳ���¼,Ȼ������ת��authorize api����oauth�߼�,����ٵ�token api��ȡtoken
// �о���Ҫ����֤ oauth ����,��challenge[Authorize],����ת��login��¼...
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
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    //app.UseHsts();
}

//app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
