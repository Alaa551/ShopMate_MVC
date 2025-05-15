using Microsoft.AspNetCore.Authentication.Cookies;

namespace ShopMate
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();

            builder.Services.AddHttpClient();

            builder.Services.AddDistributedMemoryCache();


            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                      .AddCookie(options =>
                      {
                          options.LoginPath = "/Account/Login";
                          options.LogoutPath = "/Account/Logout";
                          options.AccessDeniedPath = "/Account/AccessDenied";
                          options.ExpireTimeSpan = TimeSpan.FromDays(3);
                          options.SlidingExpiration = true;
                          options.Cookie.HttpOnly = true; // prevent access via js
                          options.Cookie.SecurePolicy = CookieSecurePolicy.None; //https only
                      });

            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromDays(1);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });

            var app = builder.Build();

            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseSession();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}
