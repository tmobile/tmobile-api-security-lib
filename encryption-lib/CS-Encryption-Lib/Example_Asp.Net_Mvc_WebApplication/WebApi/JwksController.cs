using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Sample_Asp.Net_Mvc_WebApplication.WebApi
{
    [Route("api/jwks")]
    [ApiController]
    public class JwksController : ControllerBase
    {
        [Route("v1/lab01/getjsonwebkeys")]
        [HttpGet]
        public async Task GetJsonWebKeyListAsync()
        {
            var jwksFile = AppContext.BaseDirectory + @"TestData\JwksRSAPublic.json";
            var jwksJson = System.IO.File.ReadAllText(jwksFile);
            await Response.WriteAsync(jwksJson);
        }
    }
}