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
        private KeyResolver keyResolver;

        public HomeController(
            IHttpClientFactory httpClientFactory, 
            ILogger<HomeController> logger, 
            IOptions<EncryptionOptions> encryptionOptions,
            IEncryption encryption, 
            KeyResolver keyResolver)
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
            var encryptedJweViewModel = new EncryptedJweViewModel();
            encryptedJweViewModel.PhoneNumber = "(555) 555-5555";
            encryptedJweViewModel.ErrorMessage = " ";
            encryptedJweViewModel.EncryptedJwe = string.Empty;

            return View(encryptedJweViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> Index(string submitButton, string encryptedJwe, EncryptedJweViewModel encryptedJweViewModel)
        {
            try
            {
                if (submitButton == "Encrypt")
                {
                    encryptedJweViewModel.EncryptedJwe = await this.encryption.EncryptAsync(encryptedJweViewModel.PhoneNumber, this.keyResolver, this.logger);
                }
                else if (submitButton == "Decrypt")
                {
                    encryptedJweViewModel.DecryptedPhoneNumber = await this.encryption.DecryptAsync(encryptedJwe, this.keyResolver, this.logger);
                }
            }
            catch(Exception ex)
            {
                encryptedJweViewModel.DecryptedPhoneNumber = string.Empty;
                encryptedJweViewModel.ErrorMessage = ex.Message;
                if (ex.InnerException != null)
                {
                    encryptedJweViewModel.ErrorMessage += " " + ex.InnerException.Message;
                }
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
