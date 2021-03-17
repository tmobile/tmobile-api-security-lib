using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Web;

namespace Example_Asp.Net_Mvc_WebApplication_4._5._2.Models
{
    public class EncryptedJweViewModel
    {
        [DisplayName("Enter in a phone number:")]
        public string PhoneNumber { get; set; }

        [DisplayName("Encrypted JWE:")]
        public string EncryptedJwe { get; set; }

        [DisplayName("Decrypted JWE:")]
        public string DecryptedPhoneNumber { get; set; }

        [DisplayName("Error message:")]
        public string ErrorMessage { get; set; }
    }
}