**JSON Web Encryption (JWE) component**

o .NET 4.8  and .NET Standard 2.1, using RSA or EC keys.
o .NET Core 3.1 and .NET Standard 2.1, using RSA or EC keys.

Obtains public RSA and/or EC keys from a JWKS REST Service
o Caches the public keys 
o Refreshes the public keys each hour.

Uses the public key to encrypt a PII string and creates a JWE encode string
o For RSA key, uses RSA_OAEP_256 and A256GCM
o For EC key, uses ECDH_ES_A256KW and A256GCM

Uses the private key to decrypt a JWE encode string
o The public Key Id must be the same as the private Key Id.

**C# ASP.NET MVC Sample Code:**

 **appsettings.json**
> {
>   "EncryptionOptions": {
>     "JwksUrl": "http://localhost:31102/api/jwks/v1/lab01/getjsonwebkeys",
>     "CacheDurationSeconds": 3600  // 1 hour
>     }
> }

**Startup.cs**
>         using com.tmobile.oss.security.taap.jwe;
>         using Microsoft.IdentityModel.Tokens;
> 
>         public void ConfigureServices(IServiceCollection services)
>         {
>           // IHttpClientFactory
>           services.AddHttpClient();                           
> 
>           // ILogger
>           services.AddLogging();                              
>
>           // IOptions
>            services.AddOptions();                             
>            var encryptionOptionsSection = Configuration.GetSection(nameof(EncryptionOptions));
>            services.Configure<EncryptionOptions>(encryptionOptionsSection);
>            var encryptionOptions = encryptionOptionsSection.Get<EncryptionOptions>();
>
>            // JwksService
>            services.AddSingleton(serviceProvider =>
>            {
>                var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
>                return new JwksService(httpClientFactory.CreateClient(), encryptionOptions.JwksUrl);
>            });
>
>            // KeyResolver
>            services.AddSingleton(serviceProvider =>
>            {
>                var jwksService = serviceProvider.GetService<JwksService>();
>                var privateJsonWebKeyList = new List<JsonWebKey>();
>
>                // TODO: Get private key from KeyVault
>                var privateRsaJson = File.ReadAllText(@"TestData\RsaPrivate.json");
>                var privateRsaJsonWebKey = JsonConvert.DeserializeObject<JsonWebKey>(privateRsaJson);
>                privateJsonWebKeyList.Add(privateRsaJsonWebKey);
>
>                return new KeyResolver(privateJsonWebKeyList, jwksService, encryptionOptions.CacheDurationSeconds);
>            });
>
>            // Encryption
>            services.AddTransient(serviceProvider =>
>            {
>                var keyResolver = serviceProvider.GetService<KeyResolver>();
>                var encryptionLogger = serviceProvider.GetService<ILogger<Encryption>>();
>                return new Encryption(keyResolver, encryptionLogger);
>            });
>
>            services.AddControllersWithViews();
>        }

**Controller**
	 
	public class HomeController : Controller
	{
	        private readonly Encryption encryption;

	    public HomeController(Encryption encryption)
	    {
	        this.encryption = encryption;
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
	                encryptedJweViewModel.EncryptedJwe = await this.encryption.EncryptAsync(encryptedJweViewModel.PhoneNumber);
	            }
	            else if (submitButton == "Decrypt")
	            {
	                encryptedJweViewModel.DecryptedPhoneNumber = await this.encryption.DecryptAsync(encryptedJwe);
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

**Model View**

    public class EncryptedJweViewModel   
    {
       [DisplayName("Enter in a phone number:")]
	   public string PhoneNumber { get; set; }
	   
	   [DisplayName("Encrypted JWE:")]
       public string EncryptedJwe { get; set; }

       [DisplayName("Decrypted JWE:")]
       public string DecryptedPhoneNumber { get; set; }

      [DisplayName("Error message:")]
       public string ErrorMessage { get; set; }    }

**View**

>     @using (Html.BeginForm("Index", "Home", FormMethod.Post, new { id = "encryptionForm" }))
>     {
>         <p>
>             <label class="errorMessage">@Model.ErrorMessage</label>
>         </p>
>         <p>
>             <label>Enter in a phone number:</label><br />
>             @Html.TextBoxFor(m => m.PhoneNumber)<br />
>             <input type="submit" name="submitButton" value="Encrypt">
>         </p>
>         <p>
>             <label>Encrypted JWE:</label><br />
>             <textarea name="encryptedJwe" form="encryptionForm">@Model.EncryptedJwe</textarea>
>             <input type="submit" name="submitButton" value="Decrypt">
>         </p>
>         <p>
>             <label>Decrypted phone number:</label><br />
>             <input type="text" name="decryptedPhoneNumber" value="@Model.DecryptedPhoneNumber" />
>         </p>
>     }
