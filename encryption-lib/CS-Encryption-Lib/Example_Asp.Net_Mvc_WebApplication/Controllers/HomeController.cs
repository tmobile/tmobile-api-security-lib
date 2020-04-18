using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Example_Asp.Net_Mvc_WebApplication.Models;
using Microsoft.AspNetCore.Http;
using com.tmobile.oss.security.taap.jwe;
using System.Net.Http;
using Microsoft.Extensions.Options;
using Sample_Asp.Net_Mvc_WebApplication.Models;
using Microsoft.IdentityModel.Tokens;
using System.Net;

namespace Example_Asp.Net_Mvc_WebApplication.Controllers
{
    public class HomeController : Controller
    {
        private readonly IEncryption _encryption;
        private readonly IHttpClientFactory _httpClientFactory;

        private readonly ILogger<HomeController> _logger;
        private readonly IOptions<EncryptionOptions> _encryptionOptions;

        public HomeController(
            IEncryption encryption, 
            IHttpClientFactory httpClientFactory, 
            IOptions<EncryptionOptions> encryptionOptions, 
            ILogger<HomeController> logger)
        {
            _encryption = encryption;
            _httpClientFactory = httpClientFactory;
            _encryptionOptions = encryptionOptions;
            _logger = logger;
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
        public async Task<IActionResult> Index(EncryptedJweViewModel encryptedJweViewModel)
        {
            try
            {
                var httpClient = _httpClientFactory.CreateClient();
                var jwksService = new JwksService(httpClient, _encryptionOptions.Value.JwksUrl);
                var keyResolver = new KeyResolver(new List<JsonWebKey>(), jwksService, _encryptionOptions.Value.CacheDurationSeconds);
                encryptedJweViewModel.EncryptedJwe = await _encryption.EncryptAsync(encryptedJweViewModel.PhoneNumber, keyResolver, _logger);

                //encryptedJweViewModel.EncryptedJwe = WebUtility.HtmlEncode(encryptedJweViewModel.EncryptedJwe);
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
