using com.tmobile.oss.security.taap.jwe;
using Example_Asp.Net_Mvc_WebApplication.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Example_Asp.Net_Mvc_WebApplication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            // IHttpClientFactory
            services.AddHttpClient();                           

            // ILogger<HomeService> 
            services.AddLogging();                              

            // IOptions<EncryptionOptions>
            services.AddOptions();                             
            var encryptionOptionsSection = Configuration.GetSection(nameof(EncryptionOptions));
            services.Configure<EncryptionOptions>(encryptionOptionsSection);
            
            // IKeyResolver
            var encryptionOptions = encryptionOptionsSection.Get<EncryptionOptions>();
            services.AddSingleton<IKeyResolver>(r => new KeyResolver(encryptionOptions.CacheDurationSeconds));

            // IEncryption
            services.AddTransient<IEncryption, Encryption>();

            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
