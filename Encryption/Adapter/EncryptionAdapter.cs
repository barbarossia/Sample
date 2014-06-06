namespace OASP.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Text;

    /// <summary>
    /// Base abstract class for encryption adapters, encapsulates the cipher property.
    /// </summary>
    [Serializable]
    public sealed class EncryptionAdapter : IEncryptionAdapter
    {
        /// <summary>
        /// The serilization name of the cipher data member.
        /// </summary>
        private const string CipherName = "Cipher";

        /// <summary>
        /// The cipher.
        /// </summary>
        private readonly byte[] cipher;

        /// <summary>
        /// Initializes a new instance of the EncryptionAdapter class.
        /// </summary>
        /// <param name="info">The System.Runtime.Serialization.SerializationInfo to populate with data.</param>
        /// <param name="context">The destination (see System.Runtime.Serialization.StreamingContext) for this serialization</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0", 
            Justification = "No validation required for serialization passed arguments.")]
        private EncryptionAdapter(SerializationInfo info, StreamingContext context)
        {
            // Not verifying arguments passed by serialization framework
            this.cipher = (byte[])info.GetValue(EncryptionAdapter.CipherName, typeof(byte[]));
        }

        /// <summary>
        /// Initializes a new instance of the EncryptionAdapter class.
        /// </summary>
        /// <param name="cipher">The cipher to encapsulate, cannot be null but can be empty.</param>
        /// <exception cref="ArgumentNullException">The cipher argument is null.</exception>
        private EncryptionAdapter(byte[] cipher)
            : this()
        {
            if (cipher == null)
            {
                throw new ArgumentNullException("cipher");
            }

            this.cipher = cipher;
        }

        /// <summary>
        /// Prevents a default instance of the EncryptionAdapter class from being created.
        /// </summary>
        private EncryptionAdapter()
        {
        }

        /// <summary>
        /// Creates an instance of encryption adapter.
        /// </summary>
        /// <param name="encryptor">The data encryptor, cannot be null.</param>
        /// <param name="key">The key of the cipher, it may have been used as extra entropy, cannot be null but can be empty.</param>
        /// <param name="data">The data to encrypt in a cipher, cannot be null but can be empty.</param>
        /// <returns>The encryption adapter, cannot be null.</returns>
        /// <exception cref="ArgumentNullException">The provider, key or data argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed.</exception>
        public static IEncryptionAdapter CreateAdapter(IDataEncryptor encryptor, string key, byte[] data)
        {
            if (encryptor == null)
            {
                throw new ArgumentNullException("encryptor");
            }

            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            if (data == null)
            {
                throw new ArgumentNullException("data", string.Format(CultureInfo.InvariantCulture, "Object cannot be null for key {0}", key));
            }

            return new EncryptionAdapter(encryptor.Encrypt(key, data));
        }

        /// <summary>
        /// Gets the cipher data.
        /// </summary>
        /// <returns>The cipher data, cannot be null but can be empty.</returns>
        public byte[] GetCipher()
        {
            return this.cipher;
        }

        /// <summary>
        /// Decrypts the cipher data.
        /// </summary>
        /// <param name="encryptor">The data encryptor, cannot be null.</param>
        /// <param name="key">The key of the cipher, it may have been used as extra entropy, cannot be null but can be empty.</param>
        /// <returns>The decrypted data, never but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or provider argument is null.</exception>
        /// <exception cref="CryptographicException">The decryption operation failed.</exception>
        /// <remarks>The calling context is responsible for serializing and deserializing data to and from byte[].</remarks>
        public byte[] GetData(IDataEncryptor encryptor, string key)
        {
            if (encryptor == null)
            {
                throw new ArgumentNullException("encryptor");
            }

            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            return encryptor.Decrypt(key, this.cipher);
        }

        /// <summary>
        /// Populates a System.Runtime.Serialization.SerializationInfo with the data needed to serialize the target object.
        /// </summary>
        /// <param name="info">The System.Runtime.Serialization.SerializationInfo to populate with data.</param>
        /// <param name="context">The destination (see System.Runtime.Serialization.StreamingContext) for this serialization</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0", 
            Justification = "No validation required for serialization passed arguments.")]
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // Not verifying arguments passed by serialization framework
            info.AddValue(EncryptionAdapter.CipherName, this.cipher, typeof(byte[]));
        }
    }
}
