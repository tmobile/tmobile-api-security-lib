using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;

namespace com.tmobile.oss.security.taap.poptoken.builder.mstest
{
    [TestClass]
    public class HashMapKeyValuePairTest
    {
        private Dictionary<string, string> _dictionary;

        [TestInitialize]
        public void TestInitialize()
        {
            // Arrange
            _dictionary = new Dictionary<string, string>
            {
                { "Key1", "Value1" },
                { "Key2", "Value2" },
                { "Key3", "Value3" }
            };
        }

        [TestMethod]
        public void HashMapKeyValuePair_Set_Test()
        {
            // Act
            var hashMapKeyValuePair = HashMapKeyValuePair.Set<string, string>(_dictionary);

            // Assert
            Assert.IsNotNull(hashMapKeyValuePair);
            Assert.AreEqual(3, hashMapKeyValuePair.Count);
        }

        [TestMethod]
        public void HashMapKeyValuePair_Get_Test()
        {
            // Act
            var value1 = HashMapKeyValuePair.Get<string, string>(_dictionary, "Key1");
            var value2 = HashMapKeyValuePair.Get<string, string>(_dictionary, "Key2");
            var value3 = HashMapKeyValuePair.Get<string, string>(_dictionary, "Key3");

            // Assert
            Assert.AreEqual("Value1", value1);
            Assert.AreEqual("Value2", value2);
            Assert.AreEqual("Value3", value3);
        }
    }
}
