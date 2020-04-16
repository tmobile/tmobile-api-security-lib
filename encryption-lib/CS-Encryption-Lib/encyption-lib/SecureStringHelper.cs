using Newtonsoft.Json;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace com.tmobile.oss.security.taap.jwe
{
	/// <summary>
	///  Helper class to encrypt and decrypt data 
	///  which is represented by a <seealso cref="SecureString"/> SecureString instance.
	/// </summary>
	public class SecureStringHelper //: ISecureStringHelper
	{
		private readonly string publicAsymmetricKey;

		public SecureStringHelper()
		{
			this.publicAsymmetricKey = "<RSAKeyValue><Modulus>6/7PGT9AO1ADPdnBZT3ZSImsuXfcuX9UvCjB1Zu0UliZha4bHZNcBj4VtuPJLF6ERpgJDfBqVTrT7yOMkVn4orfTlOExPedK8AWj9gTYBumGrFTDZwko1iQ5YZQ2kZGxg3QGpJhqeiEs8beFW672kXNyj5+UyeYp6R7su+fuiz8=</Modulus><Exponent>AQAB</Exponent><P>/AY3OtnrdVp6t5zVVpTqFVVHd88xgRgaO+Y4KIjzJKua1I0B8PEfIohUUai8vRbRTJZGHxwmfryQ8bkpmKXgEw==</P><Q>77fchIo2EP8jwwil//ZS+oD78eN6luKlGRljs/8wXMqaK3/x0qQHfjcBvVu0jLk1MzdNZZPiNMaxZczbJeBFpQ==</Q><DP>hZ3eBkunNE7GJTb3PLIy8SCHhZPKEUFwFzXVrFf/YP/CVNJ1pwKPmUViPvERL8c7LDm376KDHkpnJmEfFplLFQ==</DP><DQ>bniy3Tm8dNS/rE++AFmKH/t1ICIPCp3kK87xja/an8iWh9lsngANm/LJkHREnl1z0Oh5eIhQRLYUZq+jhq72KQ==</DQ><InverseQ>cXngkJq+LxEl4GzRLyk1nVcHBsKUKmqSkEgWm1qD+PtEtHMW25RR8Am2AYWU0YGa35T/hbRVG9WQhl3ZOB3pCw==</InverseQ><D>oxVWNoNANvzHELHvdLA1/GuvogeTz9iPTOv5b00HYrR5eyji8iBIQsQaq2VkOzYhwMsFzs0qHjXmCWcOl8+OAkimP7OFE6xmd0xPKaZTyFWYFBkFWbqbeAXCTcDuWH79DO0WSr35oZeppxzd4Zz+8p0GkXVgSaZgBfbcI40I6Mk=</D></RSAKeyValue>";
		}

		/// <summary>
		/// Helper method for white-listing scenarios.  Services may provide their own class which extends  
		/// SecureStringHelper and expose a method which indicates that data should (not) be encrypted
		/// because the given client has not implemented decryption capabilities at this time. 
		/// </summary>
		/// <param name="value"> The value to encrypt. </param>
		/// <exception cref="EncryptionException"> </exception>
		public virtual SecureString Encrypt<T>(T value)
		{
			return this.Encrypt<T>(value, true);
		}

		/// <summary>
		/// Helper method for white-listing scenarios.  Services may provide their own class which extends  
		/// SecureStringHelper and expose a method which indicates that clear text data is allowed
		/// because the given client has not implemented encryption capabilities at this time.
		/// </summary>
		/// <param name="value"> The value to decrypt. </param>
		/// <param name="cipherClassType"> Class of the data type for the result. </param>
		/// <param name="encryptionRequired"> If true, the value within the SecureString will be decrypted, 
		/// otherwise it will be read as clear text. If the cipher header is present, the data will be 
		/// decrypted first. </param>
		/// <returns> The clear text value. </returns>
		/// <exception cref="EncryptionException"> </exception>
		public virtual T Decrypt<T>(SecureString value)
		{
			return this.Decrypt<T>(value, true);
		}

		protected internal virtual SecureString Encrypt<T>(T value, bool encryptionRequired)
		{
			if (value == null)
			{
				return null;
			}

			string jsonValue = JsonConvert.SerializeObject(value);

			if (encryptionRequired)
			{
				byte[] data = Encoding.UTF8.GetBytes(jsonValue);
				using (var rsa = RSA.Create())
				{
					this.FromXmlString(rsa, this.publicAsymmetricKey);
					var cipherText = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
					jsonValue = Constants.CIPHER_HEADER + Convert.ToBase64String(cipherText);
				}
			}

			jsonValue = jsonValue.Trim(new char[] { '"' });

			return new SecureString(jsonValue);
		}

		protected internal virtual T Decrypt<T>(SecureString value, bool encryptionRequired)
		{
			if (value == null)
			{
				return default;
			}

			string jsonValue = value.Value;

			if (string.IsNullOrEmpty(jsonValue))
			{
				return default;
			}

			if (encryptionRequired ||
				jsonValue.StartsWith(Constants.CIPHER_HEADER, StringComparison.Ordinal))
			{
				jsonValue = jsonValue.Substring(Constants.CIPHER_HEADER.Length);
				using (var rsa = RSA.Create())
				{
					this.FromXmlString(rsa, this.publicAsymmetricKey);
					var descryptedData = rsa.Decrypt(Convert.FromBase64String(jsonValue), RSAEncryptionPadding.Pkcs1);
					jsonValue = Encoding.UTF8.GetString(descryptedData);
				}
			}

			if (!jsonValue.StartsWith("\""))
			{
				jsonValue = string.Format("\"{0}\"", jsonValue);
			}

			return JsonConvert.DeserializeObject<T>(jsonValue);
		}

		private void FromXmlString(RSA rsa, string xmlString)
		{
			RSAParameters parameters = new RSAParameters();

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.LoadXml(xmlString);

			if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
			{
				foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
				{
					switch (node.Name)
					{
						case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
						case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
						case "P": parameters.P = Convert.FromBase64String(node.InnerText); break;
						case "Q": parameters.Q = Convert.FromBase64String(node.InnerText); break;
						case "DP": parameters.DP = Convert.FromBase64String(node.InnerText); break;
						case "DQ": parameters.DQ = Convert.FromBase64String(node.InnerText); break;
						case "InverseQ": parameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
						case "D": parameters.D = Convert.FromBase64String(node.InnerText); break;
					}
				}
			}
			else
			{
				throw new Exception("Invalid XML RSA key.");
			}

			rsa.ImportParameters(parameters);
		}
	}
}
