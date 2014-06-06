namespace OASP.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// This encryptor class uses DPAPI against the current user to encrypt and decrypt data.
    /// </summary>
    [Serializable]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2229:ImplementSerializationConstructors", Justification = "Special singleton pattern must NOT provide serialization constructor.")]
    public sealed class CurrentUserDataEncryptor : ISerializableDataEncryptor
    {
        /// <summary>
        /// Hardcoded entropy to mingle with the context-supplied entropy to help the obfuscation part of the encryption
        /// </summary>
        private const string BakedInEntropy = "D134F31286F94DC3AF49D633E76CEB8F28E0BE046D694B3C9516451EFEA3648A";
        
        /// <summary>
        /// Singleton instance of the CurrentUserDataEncryptor since it is stateless.
        /// </summary>
        private static readonly CurrentUserDataEncryptor Singleton = new CurrentUserDataEncryptor();

        /// <summary>
        /// Prevents a default instance of the CurrentUserDataEncryptor class from being created.
        /// </summary>
        private CurrentUserDataEncryptor()
        {
        }

        /// <summary>
        /// Gets the singleton instance of the CurrentUserDataEncryptor class.
        /// </summary>
        public static CurrentUserDataEncryptor Instance
        {
            get { return CurrentUserDataEncryptor.Singleton; }
        }

        /// <summary>
        /// Encrypts data into a cipher.
        /// This method exists for legacy purposes.
        /// </summary>
        /// <param name="data">The data to encrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting cipher, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or data argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key.</exception>
        public static byte[] EncryptWithoutEntropy(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            return ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Decrypts a cipher into the original data.
        /// This method exists for legacy purposes.
        /// </summary>
        /// <param name="cipher">The cipher to decrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting data, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or cipher argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key or key mismatch.</exception>
        public static byte[] DecryptWithoutEntropy(byte[] cipher)
        {
            if (cipher == null)
            {
                throw new ArgumentNullException("cipher");
            }

            return ProtectedData.Unprotect(cipher, null, DataProtectionScope.CurrentUser);
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
            // Instead of serializing this object, serialize a SinlgetonSerializationHelper instead.
            info.SetType(typeof(CurrentUserDataEncryptor.SingletonSerializationHelper));
        }

        /// <summary>
        /// Encrypts data into a cipher.
        /// </summary>
        /// <param name="key">The key to the data to be used as entropy, cannot be null but can be empty.</param>
        /// <param name="data">The data to encrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting cipher, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or data argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key.</exception>
        public byte[] Encrypt(string key, byte[] data)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            if (data == null)
            {
                throw new ArgumentNullException("data", string.Format(CultureInfo.InvariantCulture, "Object cannot be null for key {0}", key));
            }

            byte[] entropy = Encoding.Unicode.GetBytes(CurrentUserDataEncryptor.BakedInEntropy + key);

            return ProtectedData.Protect(data, entropy, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Decrypts a cipher into the original data.
        /// </summary>
        /// <param name="key">The key to the data to be used as entropy, cannot be null but can be empty.</param>
        /// <param name="cipher">The cipher to decrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting data, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or cipher argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key or key mismatch.</exception>
        public byte[] Decrypt(string key, byte[] cipher)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            if (cipher == null)
            {
                throw new ArgumentNullException("cipher", string.Format(CultureInfo.InvariantCulture, "Object cannot be null for key {0}", key));
            }

            byte[] entropy = Encoding.Unicode.GetBytes(CurrentUserDataEncryptor.BakedInEntropy + key);

            return ProtectedData.Unprotect(cipher, entropy, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Creates a encryptor session.
        /// </summary>
        /// <returns>The encryptor session, never null.</returns>
        public IDataEncryptorSession CreateSession()
        {
            return new StatelessDataEncryptorSession(this);
        }

        /// <summary>
        /// Encapsulates the deserialization of the singleton TransformHelper class.
        /// </summary>
        [Serializable]
        private sealed class SingletonSerializationHelper : IObjectReference
        {
            /// <summary>
            /// Returns the real object that should be deserialized, rather than the object that the serialized stream specifies.
            /// </summary>
            /// <param name="context">The StreamingContext from which the current object is deserialized.</param>
            /// <returns>Returns the actual object that is put into the graph.</returns>
            public object GetRealObject(StreamingContext context)
            {
                // When deserializing this object, return a reference to the Singleton object instead.
                return CurrentUserDataEncryptor.Instance;
            }
        }
    }
}
