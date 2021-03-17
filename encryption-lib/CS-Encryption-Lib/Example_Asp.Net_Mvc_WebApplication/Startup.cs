using com.tmobile.oss.security.taap.jwe;
using Example_Asp.Net_Mvc_WebApplication.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;

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

            // ILogger
            services.AddLogging();                              

            // IOptions
            services.AddOptions();                             
            var encryptionOptionsSection = Configuration.GetSection(nameof(EncryptionOptions));
            services.Configure<EncryptionOptions>(encryptionOptionsSection);
            var encryptionOptions = encryptionOptionsSection.Get<EncryptionOptions>();

            // JwksService
            services.AddSingleton(serviceProvider =>
            {
                var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
                return new JwksService(httpClientFactory.CreateClient(), encryptionOptions.JwksUrl);
            });

            // KeyResolver
            services.AddSingleton(serviceProvider =>
            {
                var jwksService = serviceProvider.GetService<JwksService>();
                var privateJsonWebKeyList = new List<JsonWebKey>();

                // TODO: Get private key from KeyVault
                var privateRsaJson = File.ReadAllText(@"TestData\RsaPrivate.json");
                var privateRsaJsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(privateRsaJson);
                privateJsonWebKeyList.Add(privateRsaJsonWebKey);

                return new KeyResolver(privateJsonWebKeyList, jwksService, encryptionOptions.CacheDurationSeconds);
            });

            // Encryption
            services.AddTransient(serviceProvider =>
            {
                var keyResolver = serviceProvider.GetService<KeyResolver>();
                var encryptionLogger = serviceProvider.GetService<ILogger<Encryption>>();
                return new Encryption(keyResolver, encryptionLogger);
            });

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
