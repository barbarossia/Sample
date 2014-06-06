namespace OASP.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Security;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Microsoft.Win32;

    /// <summary>
    /// This encryptor class uses asymmetric RSA keys to encrypt and decrypt data.
    /// </summary>
    public sealed class AsymmetricDataEncryptor : IDataEncryptor
    {
        /// <summary>
        /// Hardcoded name for symmetric key data held in memory
        /// </summary>
        private const string InMemoryKeyName = "RsaKey";

        /// <summary>
        /// The length in bytes of a 2048-bits RSA key
        /// </summary>
        private const int KeyLength = 256;

        /// <summary>
        /// The length in bytes lost to the KeyLength when creating RSA encryption blocks
        /// </summary>
        private const int PadLength = 42;

        /// <summary>
        /// The path in the registry where the legacy key pair is located.
        /// </summary>
        private const string RegistryPath = "SOFTWARE\\Wow6432Node\\GSA\\GSFX";

        /// <summary>
        /// The name of the registry value where the legacy key pair is located.
        /// </summary>
        private const string RegistryValueName = "Gsfx.Scm";

        /// <summary>
        /// Delegates that returns symmetric key data on demand to avoid storing secrets in private members
        /// </summary>
        private readonly Func<string> keyData;

        /// <summary>
        /// Initializes a new instance of the AsymmetricDataEncryptor class.
        /// </summary>
        /// <param name="keyData">Delegate that procures key data on demand, cannot be null.</param>
        /// <exception cref="ArgumentNullException">The keyData argument is null.</exception>
        public AsymmetricDataEncryptor(Func<string> keyData)
            : this()
        {
            if (keyData == null)
            {
                throw new ArgumentNullException("keyData");
            }

            this.keyData = keyData;
        }

        /// <summary>
        /// Prevents a default instance of the AsymmetricDataEncryptor class from being created.
        /// </summary>
        private AsymmetricDataEncryptor()
        {
        }

        /// <summary>
        /// Creates a random RSA key and returns both its key part as XML.
        /// </summary>
        /// <returns>The key data in the clear, cannot be null or empty.</returns>
        /// <remarks>The caller must take every precaution to encrypt this result in memory and use it under the tighest of scopes when decrypted.</remarks>
        public static string GenerateKey()
        {
            using (RSACryptoServiceProvider key = new RSACryptoServiceProvider(AsymmetricDataEncryptor.KeyLength * 8))
            {
                return key.ToXmlString(true);
            }
        }

        /// <summary>
        /// Creates an AsymmetricDataEncryptor instance with a new RSA key.
        /// </summary>
        /// <returns>The asymmetric key, cannot be null.</returns>
        public static AsymmetricDataEncryptor GenerateRandomEncryptor()
        {
            // capture keydata once so that multiple calls to encrypt/decrypt for a single instance of AsymmetricDataEncryptor always behaves the same
            // but keep the key under DPAPI encryption to protect from crash dump attacks
            IStringEncryptor encryptor = StringEncryptor.Create(CurrentUserDataEncryptor.Instance);
            string keyDataCipher = encryptor.Encrypt(AsymmetricDataEncryptor.InMemoryKeyName, AsymmetricDataEncryptor.GenerateKey());
            return new AsymmetricDataEncryptor(() => encryptor.Decrypt(AsymmetricDataEncryptor.InMemoryKeyName, keyDataCipher));
        }

        /// <summary>
        /// Attempts to read the OASP asymmetric key in the registry.
        /// </summary>
        /// <returns>The asymmetric key, CAN BE NULL if the key is not found.</returns>
        /// <exception cref="SecurityException">The calling context is denied access to the registry key.</exception>
        /// <remarks>While this method instantiates a encryptor from the data found in the registry, 
        /// there is no guarantee that the data found there makes a valid key pair or properly encrypted with DPAPI.
        /// These considerations are only verified when the encryptor is actually used.</remarks>
        public static AsymmetricDataEncryptor ReadRegistryEncryptor()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(AsymmetricDataEncryptor.RegistryPath, false))
            {
                if (key == null)
                {
                    return null;
                }
                else
                {
                    string encodedCipher = key.GetValue(AsymmetricDataEncryptor.RegistryValueName) as string;

                    if (encodedCipher == null)
                    {
                        return null;
                    }
                    else
                    {
                        // The cipher bytes are DPAPI encrypted without entropy
                        // hold to this data for on-demand decryption when we want to use the key pair
                        byte[] cipher = Convert.FromBase64String(encodedCipher);

                        return new AsymmetricDataEncryptor(() => Encoding.Unicode.GetString(LocalMachineDataEncryptor.DecryptWithoutEntropy(cipher)));
                    }
                }
            }
        }

        /// <summary>
        /// This method constructs an Asymmetric data encryptor from the private key of a certificate found in the certificate store.
        /// </summary>
        /// <param name="storeLocation">The store location.</param>
        /// <param name="storeName">The store name.</param>
        /// <param name="certificateSelector">The certificate predicate selector, cannot be null.</param>
        /// <exception cref="ArgumentException">The storeLocation or storeName argument is not properly defined or the certificateName argument is null or empty or white spaces.</exception>
        /// <exception cref="InvalidOperationException">The certificate could not be found or loaded.</exception>
        /// <exception cref="SecurityException">The calling context is denied access to the certificate store.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed.</exception>
        /// <returns>The asymmetric key, cannot be null.</returns>
        public static AsymmetricDataEncryptor LoadCertificatePrivateKey(StoreLocation storeLocation, StoreName storeName, Predicate<X509Certificate2> certificateSelector)
        {
            if (!Enum.IsDefined(typeof(StoreLocation), storeLocation))
            {
                throw new ArgumentOutOfRangeException("storeLocation");
            }

            if (!Enum.IsDefined(typeof(StoreName), storeName))
            {
                throw new ArgumentOutOfRangeException("storeName");
            }

            if (certificateSelector == null)
            {
                throw new ArgumentNullException("certificateSelector");
            }

            return AsymmetricDataEncryptor.LoadCertificateKey(storeLocation, storeName, certificateSelector, certificate => certificate.PrivateKey.ToXmlString(true));
        }

        /// <summary>
        /// This method constructs an Asymmetric data encryptor from the public key of a certificate found in the certificate store.
        /// Use this method when you strictly intend to encrypt data.
        /// </summary>
        /// <param name="storeLocation">The store location.</param>
        /// <param name="storeName">The store name.</param>
        /// <param name="certificateSelector">The certificate predicate selector, cannot be null.</param>
        /// <exception cref="ArgumentException">The storeLocation or storeName argument is not properly defined or the certificateName argument is null or empty or white spaces.</exception>
        /// <exception cref="InvalidOperationException">The certificate could not be found or loaded.</exception>
        /// <exception cref="SecurityException">The calling context is denied access to the certificate store.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed.</exception>
        /// <returns>The asymmetric key, cannot be null.</returns>
        public static AsymmetricDataEncryptor LoadCertificatePublicKey(StoreLocation storeLocation, StoreName storeName, Predicate<X509Certificate2> certificateSelector)
        {
            if (!Enum.IsDefined(typeof(StoreLocation), storeLocation))
            {
                throw new ArgumentOutOfRangeException("storeLocation");
            }

            if (!Enum.IsDefined(typeof(StoreName), storeName))
            {
                throw new ArgumentOutOfRangeException("storeName");
            }

            if (certificateSelector == null)
            {
                throw new ArgumentNullException("certificateSelector");
            }

            return AsymmetricDataEncryptor.LoadCertificateKey(storeLocation, storeName, certificateSelector, certificate => certificate.PublicKey.Key.ToXmlString(false));
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

            using (RSACryptoServiceProvider algorithm = AsymmetricDataEncryptor.InstantiateAlgorithm(this.keyData))
            {
                return AsymmetricDataEncryptor.Encrypt(algorithm, data);
            }
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

            using (RSACryptoServiceProvider algorithm = AsymmetricDataEncryptor.InstantiateAlgorithm(this.keyData))
            {
                return AsymmetricDataEncryptor.Decrypt(algorithm, cipher);
            }
        }

        /// <summary>
        /// Creates a encryptor session.
        /// </summary>
        /// <returns>The encryptor session, never null.</returns>
        /// <exception cref="CryptographicException">The encryption key could not be created, probably due to malformed key data.</exception>
        public IDataEncryptorSession CreateSession()
        {
            return new AsymmetricDataEncryptor.SessionKey(this.keyData);
        }

        /// <summary>
        /// Encrypts data into a cipher.
        /// </summary>
        /// <param name="algorithm">The algorithm to use for encryption, cannot be null.</param>
        /// <param name="data">The data to encrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting cipher, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or data argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key.</exception>
        private static byte[] Encrypt(RSACryptoServiceProvider algorithm, byte[] data)
        {
            // omitting argument validation in private methods
            // KeySize is in bits, array lengths count bytes
            int blockSize = (algorithm.KeySize / 8) - AsymmetricDataEncryptor.PadLength;

            // Concatenate the result of breaking the data into chunks that are individually encrypted
            // calling 'ToArray' to avoid decrypting twice
            return AsymmetricDataEncryptor.Concatenate(AsymmetricDataEncryptor.Break(blockSize, data).Select(array => algorithm.Encrypt(array, true)).ToArray());
        }

        /// <summary>
        /// Decrypts a cipher into the original data.
        /// </summary>
        /// <param name="algorithm">The algorithm to use for decryption, cannot be null.</param>
        /// <param name="cipher">The cipher to decrypt, cannot be null but can be empty.</param>
        /// <returns>The resulting data, cannot be null but can be empty.</returns>
        /// <exception cref="ArgumentNullException">The key or cipher argument is null.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed, probably due to malformed key or key mismatch.</exception>
        private static byte[] Decrypt(RSACryptoServiceProvider algorithm, byte[] cipher)
        {
            // omitting argument validation in private methods
            // KeySize is in bits, array lengths count bytes
            int blockSize = algorithm.KeySize / 8;

            // Concatenate the result of breaking the data into chunks that are individually decrypted
            // calling 'ToArray' to avoid decrypting twice
            return AsymmetricDataEncryptor.Concatenate(AsymmetricDataEncryptor.Break(blockSize, cipher).Select(array => algorithm.Decrypt(array, true)).ToArray());
        }

        /// <summary>
        /// Instantiates a new key, the caller is responsible for disposing of this resource
        /// </summary>
        /// <param name="keyData">Delegate that procures key data on demand, cannot be null.</param>
        /// <returns>The algoriithm, cannot be null.</returns>
        /// <exception cref="CryptographicException">The encryption key could not be created, probably due to malformed key data.</exception>
        private static RSACryptoServiceProvider InstantiateAlgorithm(Func<string> keyData)
        {
            // omitting argument validation on private method, arguments validated by public methods          
            // create an ssymmetric key
            RSACryptoServiceProvider algorithm = new RSACryptoServiceProvider();

            try
            {
                try
                {
                    // set key properties
                    algorithm.FromXmlString(keyData());

                    return algorithm;
                }
                catch (XmlSyntaxException ex)
                {
                    // XmlSyntaxException not documented by FromXmlString but caugth during unit tests
                    throw new CryptographicException(ex.Message, ex);
                }
            }
            catch
            {
                if (algorithm != null)
                {
                    algorithm.Dispose();
                }

                throw;
            }
        }

        /// <summary>
        /// This method breaks an array of bytes in sub arrays no larger than the blockSize.
        /// </summary>
        /// <param name="blockSize">The maximum size of a block.</param>
        /// <param name="data">The original array of data.</param>
        /// <returns>The list of blocks created, cannot be null but can be empty.</returns>
        private static IEnumerable<byte[]> Break(int blockSize, byte[] data)
        {
            if (data.Length == 0)
            {
                yield return data;
            }
            else
            {
                // not doing argument validation on private method
                int pos = 0;

                // extract one by one each array
                while (pos < data.Length)
                {
                    int size = Math.Min(blockSize, data.Length - pos);

                    byte[] result = new byte[size];

                    Array.Copy(data, pos, result, 0, size);

                    pos += size;

                    yield return result;
                }
            }
        }

        /// <summary>
        /// This method recombines arrays of data into a single array.
        /// </summary>
        /// <param name="arrays">The arrays to concatenate.</param>
        /// <returns>The resulting array, cannnot be null but can be empty.</returns>
        private static byte[] Concatenate(byte[][] arrays)
        {
            // not doing argument validation on private method
            // get full length
            int length = arrays.Aggregate(0, (l, array) => l + array.Length);

            // create resulting array
            byte[] result = new byte[length];

            // copy one by one each array
            int pos = 0;
            foreach (byte[] array in arrays)
            {
                Array.Copy(array, 0, result, pos, array.Length);

                pos += array.Length;

                // clearing the original array now that we are done with it
                Array.Clear(array, 0, array.Length);
            }

            return result;
        }

        /// <summary>
        /// This method constructs an Asymmetric data encryptor from a certificate found in the certificate store.
        /// </summary>
        /// <param name="storeLocation">The store location.</param>
        /// <param name="storeName">The store name.</param>
        /// <param name="certificateSelector">The certificate predicate selector, cannot be null.</param>
        /// <param name="keySelector">The delegate that extracts the key data from the certificate, cannot be null.</param>
        /// <exception cref="InvalidOperationException">The certificate could not be found or loaded.</exception>
        /// <exception cref="SecurityException">The calling context is denied access to the certificate store.</exception>
        /// <exception cref="CryptographicException">The encryption operation failed.</exception>
        /// <returns>The asymmetric key, cannot be null.</returns>
        private static AsymmetricDataEncryptor LoadCertificateKey(StoreLocation storeLocation, StoreName storeName, Predicate<X509Certificate2> certificateSelector, Func<X509Certificate2, string> keySelector)
        {
            // argument validation done in public method for first three arguments, last argument trusted to be not null
            X509Store store = null;

            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2 certificate = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(cert => certificateSelector(cert));

                if (certificate != null)
                {
                    // capture keydata once so that multiple calls to encrypt/decrypt for a single instance of AsymmetricDataEncryptor always behaves the same
                    // but keep the key under DPAPI encryption to protect from crash dump attacks
                    IStringEncryptor encryptor = StringEncryptor.Create(CurrentUserDataEncryptor.Instance);
                    string keyDataCipher = encryptor.Encrypt(AsymmetricDataEncryptor.InMemoryKeyName, keySelector(certificate));
                    return new AsymmetricDataEncryptor(() => encryptor.Decrypt(AsymmetricDataEncryptor.InMemoryKeyName, keyDataCipher));
                }
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                    store = null;
                }
            }

            throw new InvalidOperationException("The requested certificate could not be loaded.");
        }

        /// <summary>
        /// This class encapsulates the statefulness of an encryption key to be used for multiple operations.
        /// </summary>
        private sealed class SessionKey : IDataEncryptorSession
        {
            /// <summary>
            /// Delegates that returns symmetric key data on demand to avoid storing secrets in private members
            /// </summary>
            private readonly Func<string> keyData;

            /// <summary>
            /// The disposed flag.
            /// </summary>
            private bool disposed;

            /// <summary>
            /// The encryption and decryption algorithm.
            /// </summary>
            private RSACryptoServiceProvider algorithm;

            /// <summary>
            /// Initializes a new instance of the SessionKey class.
            /// </summary>
            /// <param name="keyData">Delegate that procures key data on demand, cannot be null.</param>
            /// <exception cref="ArgumentNullException">The keyData argument is null.</exception>
            /// <exception cref="CryptographicException">The encryption key could not be created, probably due to malformed key data.</exception>
            public SessionKey(Func<string> keyData)
                : this()
            {
                // omitting arg validation since this type in private
                this.keyData = keyData;

                this.algorithm = AsymmetricDataEncryptor.InstantiateAlgorithm(this.keyData);
            }

            /// <summary>
            /// Prevents a default instance of the SessionKey class from being created.
            /// </summary>
            private SessionKey()
            {
                this.disposed = false;
            }

            /// <summary>
            /// Finalizes an instance of the SessionKey class.
            /// </summary>
            ~SessionKey()
            {
                this.Dispose(false);
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

                if (this.disposed)
                {
                    throw new ObjectDisposedException("This instance has been disposed.");
                }

                return AsymmetricDataEncryptor.Encrypt(this.algorithm, data);
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

                if (this.disposed)
                {
                    throw new ObjectDisposedException("This instance has been disposed.");
                }

                return AsymmetricDataEncryptor.Decrypt(this.algorithm, cipher);
            }

            /// <summary>
            /// Creates a encryptor session.
            /// </summary>
            /// <returns>The encryptor session, never null.</returns>
            /// <exception cref="CryptographicException">The encryption key could not be created, probably due to malformed key data.</exception>
            public IDataEncryptorSession CreateSession()
            {
                return new AsymmetricDataEncryptor.SessionKey(this.keyData);
            }

            /// <summary>
            /// Disposes the current instance releasing resources.
            /// </summary>
            public void Dispose()
            {
                this.Dispose(true);
                GC.SuppressFinalize(this);
            }

            /// <summary>
            /// Disposes the current instance releasing resources.
            /// </summary>
            /// <param name="disposing">True if called from client code, false if called from finalizer.</param>
            private void Dispose(bool disposing)
            {
                if (!this.disposed)
                {
                    if (disposing)
                    {
                        if (this.algorithm != null)
                        {
                            this.algorithm.Dispose();
                            this.algorithm = null;
                        }
                    }

                    this.disposed = true;
                }
            }
        }
    }
}
