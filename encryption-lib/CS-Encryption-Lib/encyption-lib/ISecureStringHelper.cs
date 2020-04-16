using System;

namespace com.tmobile.oss.security.taap.jwe
{
    public interface ISecureStringHelper
    {
        T Decrypt<T>(SecureString value, Type cipherClass);
        SecureString Encrypt<T>(string jwksUrl, T value);
    }
}