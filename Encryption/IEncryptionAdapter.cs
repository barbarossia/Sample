namespace OASP.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Text;

    /// <summary>
    /// This interface is an adpater on top of a cipher so that serialization and deserialization can match in different contexts.
    /// </summary>
    public interface IEncryptionAdapter : ISerializable
    {
        /// <summary>
        /// Gets the cipher data.
        /// </summary>
        /// <returns>The cipher data, cannot be null but can be empty.</returns>
        byte[] GetCipher();

        /// <summary>
        /// Decrypts the cipher data.
        /// </summary>
        /// <param name="encryptor">The data encryptor, cannot be null.</param>
        /// <param name="key">The key of the cipher, it may have been used as extra entropy, cannot be null but can be empty.</param>
        /// <returns>The decrypted data, never but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or provider argument is null.</exception>
        /// <exception cref="CryptographicException">The decryption operation failed.</exception>
        /// <remarks>The calling context is responsible for serializing and deserializing data to and from byte[].</remarks>
        byte[] GetData(IDataEncryptor encryptor, string key);
    }
}
