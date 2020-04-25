//using System;
//using Newtonsoft.Json;

//namespace com.tmobile.oss.security.taap.jwe
//{
//    /// <summary>
//    /// Cipher Serializer / Deserialize
//    /// </summary>
//    public class CipherSerializer : ICipherSerializer
//    {
//        /// <summary>
//        /// Deserialize
//        /// </summary>
//        /// <typeparam name="T">Type</typeparam>
//        /// <param name="value">Serialize string</param>
//        /// <returns>Object</returns>
//        public T Deserialize<T>(string value)
//        {
//            try
//            {
//                return JsonConvert.DeserializeObject<T>(value); ;
//            }
//            catch (Exception ex)
//            {
//                throw new SerializerException("Unable to deserializer value.", ex);
//            }
//        }

//        /// <summary>
//        /// Serialize
//        /// </summary>
//        /// <typeparam name="T">Type</typeparam>
//        /// <param name="value">Object</param>
//        /// <returns>Serialize string</returns>
//        public string Serialize<T>(T value)
//        {
//            try
//            {
//                return JsonConvert.SerializeObject(value);
//            }
//            catch (Exception ex)
//            {
//                throw new SerializerException("Unable to serializer value.", ex);
//            }
//        }
//    }
//}
