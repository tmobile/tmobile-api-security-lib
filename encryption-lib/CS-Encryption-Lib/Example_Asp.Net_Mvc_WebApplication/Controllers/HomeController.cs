using com.tmobile.oss.security.taap.jwe;
using Example_Asp.Net_Mvc_WebApplication.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;

namespace Example_Asp.Net_Mvc_WebApplication.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly ILogger<HomeController> logger;
        private readonly IOptions<EncryptionOptions> encryptionOptions;
        private readonly IEncryption encryption;
        private IKeyResolver keyResolver;

        public HomeController(
            IHttpClientFactory httpClientFactory, 
            ILogger<HomeController> logger, 
            IOptions<EncryptionOptions> encryptionOptions,
            IEncryption encryption, 
            IKeyResolver keyResolver)
        {
            this.httpClientFactory = httpClientFactory;
            this.logger = logger;
            this.encryptionOptions = encryptionOptions;
            this.encryption = encryption;
            this.keyResolver = keyResolver;
        }

        [HttpGet]
        public IActionResult Index()
        {
            if(this.keyResolver.GetJwksService() == null)
            {
                var httpClient = this.httpClientFactory.CreateClient();
                var jwkUrl = this.encryptionOptions.Value.JwksUrl;
                var jwksService = new JwksService(httpClient, jwkUrl);

                this.keyResolver.SetJwksService(jwksService);
            }

            var encryptedJweViewModel = new EncryptedJweViewModel();
            encryptedJweViewModel.PhoneNumber = "(555) 555-5555";
            encryptedJweViewModel.ErrorMessage = " ";
            encryptedJweViewModel.EncryptedJwe = string.Empty;
            return View(encryptedJweViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> Index(EncryptedJweViewModel encryptedJweViewModel)
        {
            try
            {
                var phoneNumber = encryptedJweViewModel.PhoneNumber;
                encryptedJweViewModel.EncryptedJwe = await this.encryption.EncryptAsync(phoneNumber, this.keyResolver, this.logger);
            }
            catch(Exception ex)
            {
                encryptedJweViewModel.ErrorMessage = ex.Message;
            }

            return View(encryptedJweViewModel);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
