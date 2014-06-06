namespace OASP.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.Security;
    using System.Text;

    /// <summary>
    /// This class encapsulates the serialization and deserialization of data using a BinaryFormatter.
    /// This class is serializable and acts as a wrapper around the data.
    /// </summary>
    [Serializable]
    public sealed class BinarySerializationAdapter : ISerializationAdapter
    {
        /// <summary>
        /// Serialization name of the dataType field.
        /// </summary>
        private const string DataTypeName = "DataType";

        /// <summary>
        /// Serialization name of the adapter field.
        /// </summary>
        private const string AdapterName = "Adapter";

        /// <summary>
        /// Formatter for data serialization and deserialization for in-memory encryption and decryption.
        /// </summary>
        private static readonly BinaryFormatter Formatter = new BinaryFormatter();

        /// <summary>
        /// Data type of the value serialized.
        /// </summary>
        private Type dataType;

        /// <summary>
        /// Encryption adapter for the data serialized.
        /// </summary>
        private IEncryptionAdapter adapter;

        /// <summary>
        /// Prevents a default instance of the BinarySerializationAdapter class from being created.
        /// </summary>
        private BinarySerializationAdapter()
        {
        }

        /// <summary>
        /// Initializes a new instance of the BinarySerializationAdapter class.
        /// </summary>
        /// <param name="info">The System.Runtime.Serialization.SerializationInfo to populate with data.</param>
        /// <param name="context">The destination (see System.Runtime.Serialization.StreamingContext) for this serialization</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0",
            Justification = "No validation required for serialization passed arguments.")]
        private BinarySerializationAdapter(SerializationInfo info, StreamingContext context)
        {
            // Not verifying arguments passed by serialization framework
            this.dataType = (Type)info.GetValue(BinarySerializationAdapter.DataTypeName, typeof(Type));
            this.adapter = (IEncryptionAdapter)info.GetValue(BinarySerializationAdapter.AdapterName, typeof(IEncryptionAdapter));
        }

        /// <summary>
        /// Gets the original data type of the value, for lookup purposes.
        /// </summary>
        public Type DataType
        {
            get { return this.dataType; }
        }

        /// <summary>
        /// Gets the encapsulated encryption adapter.
        /// </summary>
        public IEncryptionAdapter EncryptionAdapter
        {
            get { return this.adapter; }
        }

        /// <summary>
        /// This methods serializes and encrypts the original object.
        /// </summary>
        /// <param name="encryptDelegate">A delegate provided by the calling context to provide the encryption, cannot be null.</param>
        /// <param name="value">The value to serialize, cannot be null.</param>
        /// <returns>The decrypted and desrialized object, cannot be null.</returns>
        /// <exception cref="ArgumentNullException">The encryptDelegate or value argument is null.</exception>
        /// <exception cref="CryptographicException">The decryption operation failed.</exception>
        /// <exception cref="SerializationException">The deserialization operation failed.</exception>
        /// <exception cref="SecurityException">The deserialization operation failed due to security restrictions.</exception>
        public static BinarySerializationAdapter CreateAdapter(Func<byte[], IEncryptionAdapter> encryptDelegate, object value)
        {
            if (encryptDelegate == null)
            {
                throw new ArgumentNullException("encryptDelegate");
            }

            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            BinarySerializationAdapter element = new BinarySerializationAdapter();

            using (MemoryStream stream = new MemoryStream())
            {
                BinarySerializationAdapter.Formatter.Serialize(stream, value);
                stream.Position = 0;

                byte[] data = stream.ToArray();

                element.adapter = encryptDelegate(data);

                // clear the data array as soon as possible
                Array.Clear(data, 0, data.Length);

                element.dataType = value.GetType();
            }

            return element;
        }

        /// <summary>
        /// This methods decrypts and deserializes back to the original object.
        /// </summary>
        /// <param name="decryptDelegate">A delegate provided by the calling context to provide the decryption, cannot be null.</param>
        /// <returns>The decrypted and desrialized object, cannot be null.</returns>
        /// <exception cref="ArgumentNullException">The decryptDelegate argument is null.</exception>
        /// <exception cref="CryptographicException">The decryption operation failed.</exception>
        /// <exception cref="SerializationException">The deserialization operation failed.</exception>
        /// <exception cref="SecurityException">The deserialization operation failed due to security restrictions.</exception>
        public object GetData(Func<IEncryptionAdapter, byte[]> decryptDelegate)
        {
            if (decryptDelegate == null)
            {
                throw new ArgumentNullException("decryptDelegate");
            }

            object result = null;

            byte[] data = decryptDelegate(this.adapter);

            using (MemoryStream stream = new MemoryStream(data))
            {
                result = BinarySerializationAdapter.Formatter.Deserialize(stream);

                // clear the data array as soon as possible
                Array.Clear(data, 0, data.Length);

                return result;
            }
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
            info.AddValue(BinarySerializationAdapter.DataTypeName, this.dataType, typeof(Type));
            info.AddValue(BinarySerializationAdapter.AdapterName, this.adapter, typeof(IEncryptionAdapter));
        }
    }
}
