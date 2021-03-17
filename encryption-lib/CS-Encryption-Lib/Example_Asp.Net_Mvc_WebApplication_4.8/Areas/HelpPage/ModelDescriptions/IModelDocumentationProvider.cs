using System;
using System.Reflection;

namespace Example_Asp.Net_Mvc_WebApplication_4._5._2.Areas.HelpPage.ModelDescriptions
{
    public interface IModelDocumentationProvider
    {
        string GetDocumentation(MemberInfo member);

        string GetDocumentation(Type type);
    }
}