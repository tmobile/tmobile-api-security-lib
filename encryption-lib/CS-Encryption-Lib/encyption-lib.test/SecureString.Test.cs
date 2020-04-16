//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using Newtonsoft.Json;

//namespace com.tmobile.oss.security.taap.jwe.test

//{
//	[TestClass]
//	public class SecureStringTest
//	{
//		[TestMethod]
//		public virtual void SecureString_ToString()
//		{
//			// Arrange
//			var actualValue = "cipher";
//			var expectedValue = "******";
//			var secureString = new SecureString(actualValue);

//			// Act
//			var returnedValue = secureString.ToString();

//			// Assert
//			Assert.AreEqual(expectedValue, returnedValue);
//		}

//		[TestMethod]
//		public virtual void SecureString_ValueMasked()
//		{
//			// Arrange
//			var actualValue = "cipher";
//			var expectedValue = "******";
//			var secureString = new SecureString(actualValue);

//			// Act
//			var returnedValue = secureString.ValueMasked;

//			// Assert
//			Assert.AreEqual(expectedValue, returnedValue);
//		}

//		[TestMethod]
//		public virtual void SecureString_Value()
//		{
//			// Arrange
//			var actualValue = "cipher";
//			var expectedValue = "cipher";
//			var secureString = new SecureString(actualValue);

//			// Act
//			var returnedValue = secureString.Value;

//			// Assert
//			Assert.AreEqual(expectedValue, returnedValue);
//		}

//		[TestMethod]
//		public virtual void SecureString_SerializedJson_Value()
//		{
//			// Arrange
//			var actualValue = "cipher";
//			var expectedValue = "{\"Value\":\"******\"}";
//			var secureString = new SecureString(actualValue);

//			// Act
//			string json = JsonConvert.SerializeObject(secureString);

//			// Assert
//			Assert.AreEqual(expectedValue, json);
//		}
//	}
//}
