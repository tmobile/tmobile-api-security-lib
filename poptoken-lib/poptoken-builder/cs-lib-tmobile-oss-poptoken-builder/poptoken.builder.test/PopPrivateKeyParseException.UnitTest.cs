using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace com.tmobile.oss.security.taap.poptoken.builder.mstest
{
    [TestClass]
    public class PopPrivateKeyParseExceptionTest
    {
        [TestMethod]
        public void PopPrivateKeyParseException_CustomConstrutor1_Test()
        {
            // Arrange
            var message = "An exception occurred";

            // Act
            var popPrivateKeyParseException = new PopPrivateKeyParseException(message);

            // Assert
            Assert.AreEqual(message, popPrivateKeyParseException.Message);
        }

        [TestMethod]
        public void PopPrivateKeyParseException_CustomConstrutor2_Test()
        {
            // Arrange
            var message1 = "An exception occurred";
            var message2 = "The exception was caused by invalid key";
            var exception = new Exception(message2);

            // Act
            var popPrivateKeyParseException = new PopPrivateKeyParseException(message1, exception);

            // Assert
            Assert.AreEqual(message1, popPrivateKeyParseException.Message);
            Assert.AreEqual(message2, popPrivateKeyParseException.InnerException.Message);
        }
    }
}
