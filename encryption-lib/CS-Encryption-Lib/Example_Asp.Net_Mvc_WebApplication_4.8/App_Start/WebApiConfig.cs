using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Web.Http;

namespace Example_Asp.Net_Mvc_WebApplication_4._5._2
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "WebApi",
                routeTemplate: "api/Jwks/GetJsonWebKeyListAsync",
                defaults: new { controller = "Jwks", action = "GetJsonWebKeyListAsync" });

        }
    }    
}
