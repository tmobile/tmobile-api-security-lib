using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace com.tmobile.oss.security.taap.poptoken.builder.test
{
    [TestClass]
    public class PopTokenBuilderExceptionTest
    {
        [TestMethod]
        public void PopTokenBuilderException_Version_Test()
        {
            // Arrange
            var message = "An exception occurred";

            // Act
            var popTokenBuilderException = new PopTokenBuilderException(message);

            // Assert
            Assert.AreEqual(message, popTokenBuilderException.Message);
        }
    }
}
