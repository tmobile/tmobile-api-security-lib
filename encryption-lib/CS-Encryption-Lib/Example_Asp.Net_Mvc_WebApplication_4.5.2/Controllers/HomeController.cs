using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using com.tmobile.oss.security.taap.jwe;
using Example_Asp.Net_Mvc_WebApplication_4._5._2.Models;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Example_Asp.Net_Mvc_WebApplication_4._5._2.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Title = "Home Page";

            var encryptedJweViewModel = new EncryptedJweViewModel();
            encryptedJweViewModel.PhoneNumber = "(555) 555-5555";
            encryptedJweViewModel.ErrorMessage = " ";
            encryptedJweViewModel.EncryptedJwe = string.Empty;

            return View(encryptedJweViewModel);
        }

        [HttpPost]
        public async Task<ActionResult> Index(string submitButton, string encryptedJwe, EncryptedJweViewModel encryptedJweViewModel)
        {
            try
            {
                var jwksUrl = ConfigurationManager.AppSettings["JwksUrl"];
                var cacheDurationSeconds = long.Parse(ConfigurationManager.AppSettings["CacheDurationSeconds"]);

                var privateJsonWebKeyList = new List<JsonWebKey>();
                var privateRsaJson = System.IO.File.ReadAllText(AppDomain.CurrentDomain.RelativeSearchPath + @"\TestData\RsaPrivate.json");
                var privateRsaJsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(privateRsaJson);
                privateJsonWebKeyList.Add(privateRsaJsonWebKey);

                var httpClient = new HttpClient();

                var jwksService = new JwksService(httpClient, jwksUrl);
                var keyResolver = new KeyResolver(privateJsonWebKeyList, jwksService, cacheDurationSeconds);
                var encryption = new Encryption(keyResolver);  //, null); // this.logger.Object);

                if (submitButton == "Encrypt")
                {
                    encryptedJweViewModel.EncryptedJwe = await encryption.EncryptAsync(encryptedJweViewModel.PhoneNumber);
                }
                else if (submitButton == "Decrypt")
                {
                    encryptedJweViewModel.DecryptedPhoneNumber = await encryption.DecryptAsync(encryptedJwe);
                }
            }
            catch (Exception ex)
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

    }
}
