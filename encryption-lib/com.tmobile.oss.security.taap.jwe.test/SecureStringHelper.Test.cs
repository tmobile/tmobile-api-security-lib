//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using System;

//namespace com.tmobile.oss.security.taap.jwe.builder

//{
//	[TestClass]
//	public class SecureStringHelperTest
//	{
//		public SecureStringHelperTest()
//		{
//		}

//		[TestMethod]
//		public virtual void SecureStringHelper_EncryptDecryptString_Success()
//		{
//			// Arrange
//			var expected = "Test data.";
//			var secureStringHelper = new SecureStringHelper();

//			// Act
//			var cipherData = secureStringHelper.Encrypt(expected);
//			var actual = secureStringHelper.Decrypt<string>(cipherData);

//			// Assert
//			Assert.AreEqual(expected, actual);
//		}

//		[TestMethod]
//		public virtual void SecureStringHelper_EncryptDecryptDateTime_Success()
//		{
//			// Arrange
//			var expectedDate = DateTime.Now;
//			var secureStringHelper = new SecureStringHelper();

//			// Act
//			var cipherWhen = secureStringHelper.Encrypt<DateTime>(expectedDate);
//			var actualDate = secureStringHelper.Decrypt<DateTime>(cipherWhen);

//			// Assert
//			Assert.IsNotNull(actualDate);
//			Assert.AreEqual(expectedDate, actualDate);
//		}

//		[TestMethod]
//		public virtual void SecureStringHelper_DecryptIfHeaderFound()
//		{
//			// Arrange
//			var expected = "Test data.";
//			var secureStringHelper = new SecureStringHelper();

//			// Act
//			var cipherData = secureStringHelper.Encrypt(expected);
//			var actual = secureStringHelper.Decrypt<string>(cipherData, false);

//			// Assert
//			Assert.AreEqual(expected, actual);
//		}

//		[TestMethod]
//		public virtual void SecureStringHelper_WhitelistedDecryption()
//		{
//			// Arrange
//			var expected = "Test data.";
//			var secureStringHelper = new SecureStringHelper();

//			// Act
//			var cipherData = new SecureString(expected);
//			var actual = secureStringHelper.Decrypt<string>(cipherData, false);

//			// Assert
//			Assert.AreEqual(expected, actual);
//		}

//		[TestMethod]
//		public virtual void SecureStringHelper_WhitelistedEncryption()
//		{
//			// Arrange
//			var expected = "Test data.";
//			var secureStringHelper = new SecureStringHelper();

//			// Act
//			var cipherData = secureStringHelper.Encrypt<string>(expected, false);

//			// Assert
//			Assert.AreEqual(expected, cipherData.Value);
//		}

//		[TestMethod]
//		public virtual void SecureStringHelper_DecryptNullData()
//		{
//			// Arrange
//			var secureStringHelper = new SecureStringHelper();

//			// Act
//			var actual = secureStringHelper.Decrypt<string>(null);

//			// Assert
//			Assert.AreEqual(null, actual);
//		}

//		[TestMethod]
//		public virtual void SecureStringHelper_DecryptEmptySecureString()
//		{
//			// Arrange
//			var secureStringHelper = new SecureStringHelper();
//			var cipherData = new SecureString(string.Empty);

//			// Act
//			var actual = secureStringHelper.Decrypt<string>(cipherData);

//			// Assert
//			Assert.AreEqual(null, actual);
//		}
//	}
//}