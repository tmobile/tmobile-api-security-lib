using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace com.tmobile.oss.security.taap.poptoken.builder.test
{
    [TestClass]
    public class PopTokenBuilderUtilsUnitTest
    {
        //[TestMethod]
        //public void PopTokenBuilderUtils_GenerateNewRsaSecurityKey_Test()
        //{
        //    // Arrange
        //    var keySizeInBits = 2048;
        //    var issuer = "Me";
        //    var audience = "You";

        //    // Act
        //    var rsaSecurityKey = PopTokenBuilderUtils.GenerateNewRsaSecurityKey(keySizeInBits);
        //    var jwt = PopTokenBuilderUtils.CreateToken(rsaSecurityKey, issuer, audience);
        //    var tokenValidationResult = PopTokenBuilderUtils.ValidateToken(jwt, rsaSecurityKey, issuer, audience);
            
        //        // Assert
        //    Assert.IsNotNull(rsaSecurityKey);
        //    Assert.AreEqual(PrivateKeyStatus.Exists, rsaSecurityKey.PrivateKeyStatus);
        //    Assert.AreEqual("2048", rsaSecurityKey.KeySize.ToString());
            
        //    Assert.IsFalse(string.IsNullOrEmpty(jwt));

        //    Assert.IsNotNull(tokenValidationResult);
        //    Assert.IsTrue(tokenValidationResult.IsValid);

        //}
    }
}
