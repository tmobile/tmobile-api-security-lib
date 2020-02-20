using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;

namespace com.tmobile.oss.security.taap.poptoken.builder.test
{
    [TestClass]
    public class HashMapKeyValuePairTest
    {
        private Dictionary<string, string> dictionary;

        [TestInitialize]
        public void TestInitialize()
        {
            // Arrange
            dictionary = new Dictionary<string, string>();
            dictionary.Add("Key1", "Value1");
            dictionary.Add("Key2", "Value2");
            dictionary.Add("Key3", "Value3");
        }

        [TestMethod]
        public void HashMapKeyValuePair_Set_Test()
        {
            // Act
            var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(dictionary);

            // Assert
            Assert.IsNotNull(hashMapKeyValuePair);
            Assert.AreEqual(3, hashMapKeyValuePair.Count);
        }

        [TestMethod]
        public void HashMapKeyValuePair_Get_Test()
        {
            // Act
            var value1 = HashMapKeyValuePair.Get<string, string>(dictionary, "Key1");
            var value2 = HashMapKeyValuePair.Get<string, string>(dictionary, "Key2");
            var value3 = HashMapKeyValuePair.Get<string, string>(dictionary, "Key3");

            // Assert
            Assert.AreEqual("Value1", value1);
            Assert.AreEqual("Value2", value2);
            Assert.AreEqual("Value3", value3);
        }
    }
}
