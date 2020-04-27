using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Example_Asp.Net_Mvc_WebApplication_4._5._2.Areas.HelpPage.ModelDescriptions
{
    public class EnumTypeModelDescription : ModelDescription
    {
        public EnumTypeModelDescription()
        {
            Values = new Collection<EnumValueDescription>();
        }

        public Collection<EnumValueDescription> Values { get; private set; }
    }
}