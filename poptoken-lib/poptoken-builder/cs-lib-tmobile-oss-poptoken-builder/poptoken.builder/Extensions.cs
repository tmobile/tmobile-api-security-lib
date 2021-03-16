/*
 * Copyright 2020 T-Mobile US, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;

namespace com.tmobile.oss.security.taap.poptoken.builder
{
    /// <summary>
    /// Extensions
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Get Description
        /// </summary>
        /// <param name="enumItem">Enum Item</param>
        /// <returns>Description</returns>
        public static string GetDescription(this Enum enumItem)
        {
            return enumItem.GetType()
                           .GetField(enumItem.ToString())
                           .GetCustomAttributes(typeof(DescriptionAttribute), false)
                           .Select(a => ((DescriptionAttribute)a).Description)
                           .FirstOrDefault() ?? enumItem.ToString();
        }

        /// <summary>
        /// From Xml Rsa Pem Key
        /// </summary>
        /// <param name="rsa">RSA</param>
        /// <param name="xmlRsaXmlKey">XmlRsaXmlKey</param>
        public static void FromXmlRsaPemKey(this RSA rsa, string xmlRsaXmlKey)
        {
            if (string.IsNullOrEmpty(xmlRsaXmlKey) ||
                !xmlRsaXmlKey.StartsWith("<RSAKeyValue>"))
            {
                throw new ArgumentException("Invalid RSA key string. Must use XML format with <RSAKeyValue> as root.", "xmlRsaPemKey");
            }

            var rsaParameters = new RSAParameters();
            var xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(xmlRsaXmlKey);

            foreach (XmlNode xmlNode in xmlDocument.DocumentElement.ChildNodes)
            {
                switch (xmlNode.Name)
                {
                    case "Modulus":
                        rsaParameters.Modulus = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                    case "Exponent":
                        rsaParameters.Exponent = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                    case "P":
                        rsaParameters.P = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                    case "Q":
                        rsaParameters.Q = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                    case "DP":
                        rsaParameters.DP = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                    case "DQ":
                        rsaParameters.DQ = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                    case "InverseQ":
                        rsaParameters.InverseQ = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                    case "D":
                        rsaParameters.D = (string.IsNullOrEmpty(xmlNode.InnerText) ? null : Convert.FromBase64String(xmlNode.InnerText));
                        break;
                }
            }

            rsa.ImportParameters(rsaParameters);
        }
    }
}
