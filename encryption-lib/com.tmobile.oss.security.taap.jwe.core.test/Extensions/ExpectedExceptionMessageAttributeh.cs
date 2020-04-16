using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace com.tmobile.oss.security.taap.jwe.test
{
    public class ExpectedExceptionMessageAttribute : ExpectedExceptionBaseAttribute
    {
        public Type ExceptionType { get; set; }

        public string ExpectedMessage { get; set; }

        public ExpectedExceptionMessageAttribute(Type exceptionType)
        {
            this.ExceptionType = exceptionType;
        }

        public ExpectedExceptionMessageAttribute(Type exceptionType, string expectedMessage)
        {
            this.ExceptionType = exceptionType;
            this.ExpectedMessage = expectedMessage;
        }

        protected override void Verify(Exception e)
        {
            if (e.GetType() != this.ExceptionType)
            {
                Assert.Fail($"ExpectedExceptionMessageAttribute failed. Expected exception type: {this.ExceptionType.FullName}. " +
                    $"Actual exception type: {e.GetType().FullName}. Exception message: {e.Message}");
            }

            var actualMessage = e.Message.Trim();
            if (this.ExpectedMessage != null)
            {
                Assert.AreEqual(this.ExpectedMessage, actualMessage);
            }

            // Debug.WriteLine($"ExpectedExceptionMessageAttribute:{actualMessage}");
        }
    }
}
