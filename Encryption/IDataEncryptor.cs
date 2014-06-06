namespace OASP.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Text;

    /// <summary>
    /// Encryption interface.
    /// </summary>
    public interface IDataEncryptor
    {
        /// <summary>
        /// Encrypts data into a cipher.
        /// </summary>
        /// <param name="key">The key to the data to be used as entropy, cannot be null but can be empty.</param>
        /// <param name="data">The data to encrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting cipher, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or data argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key.</exception>
        byte[] Encrypt(string key, byte[] data);

        /// <summary>
        /// Decrypts a cipher into the original data.
        /// </summary>
        /// <param name="key">The key to the data to be used as entropy, cannot be null but can be empty.</param>
        /// <param name="cipher">The cipher to decrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting data, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or cipher argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key or key mismatch.</exception>
        byte[] Decrypt(string key, byte[] cipher);

        /// <summary>
        /// Creates a encryptor session.
        /// </summary>
        /// <returns>The encryptor session, never null.</returns>
        /// <exception cref="CryptographicException">The encryption key could not be created, probably due to malformed key data.</exception>
        IDataEncryptorSession CreateSession();
    }

    /// <summary>
    /// Use this interface when you need to do multiple encryption or decryption operations with a single key.
    /// Do not cache an instance of this interface in data members and call Dispose in the tighest of scopes.
    /// </summary>
    public interface IDataEncryptorSession : IDataEncryptor, IDisposable
    {
    }

    /// <summary>
    /// Use this interface when you need to have a class that acts as an encryptort but that can also be serialized and deserialized
    /// </summary>
    public interface ISerializableDataEncryptor : IDataEncryptor, ISerializable
    {
    }
}
