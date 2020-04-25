using System.Web;
using System.Web.Mvc;

namespace Example_Asp.Net_Mvc_WebApplication_4._5._2
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
