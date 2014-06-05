using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Cryptography;
using OASP.Encryption;

namespace CommonWorkflow.WorkFlowContext
{
    [Serializable]
    public class WorkflowContext : IWorkflowContext, ISerializable, IEquatable<WorkflowContext>
    {
        #region Fields

        private static readonly BinaryFormatter DictionaryFormatter = new BinaryFormatter();

        /// <summary>
        /// Default group name to be used when user does not want to use it
        /// </summary>
        private string defaultGroupName = "Default";

        /// <summary>
        /// Gets or Sets the Item Collection
        /// </summary>
        private Dictionary<string, object> items { get; set; }

        /// <summary>
        /// Collection for Group
        /// </summary>
        private Dictionary<string, List<string>> groups { get; set; }

        /// <summary>
        /// Data encryptor
        /// </summary>
        private ISerializableDataEncryptor encryptor;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the WorkflowContext class.
        /// This constructor assumes server affinity and uses current user credentials for in-memory data protection.
        /// </summary>
        public WorkflowContext()
        {
            items = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            groups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            Id = Guid.NewGuid();
            this.Encryptor = CurrentUserDataEncryptor.Instance;
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets or sets the data encryptor 
        /// </summary>
        public ISerializableDataEncryptor Encryptor
        {
            get
            {
                return this.encryptor;
            }

            set
            {
                this.encryptor = value ?? CurrentUserDataEncryptor.Instance;
            }
        }

        /// <summary>
        /// Gets or sets the default group name for the Items.Add.
        /// </summary>
        /// <value>
        /// The group name.
        /// </value>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null or whitespace.</exception>
        public string DefaultGroupName
        {
            get
            {
                return defaultGroupName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException("value", "DefaultGroupName Value cannot be null or empty");
                }

                defaultGroupName = value;
            }
        }

        /// <summary>
        /// Gets or sets and Sets context ID
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Indexer access
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null or whitespace.</exception>
        /// <returns> value as an object</returns>
        public object this[string key]
        {
            get
            {
                return Get(key);
            }
            set
            {
                Add(key, value);
            }
        }

        /// <summary>
        /// Gets the count of the Group dictionary.
        /// </summary>
        public int GroupCount
        {
            get
            {
                return this.groups.Count;
            }
        }

        /// <summary>
        /// Gets the count of the Item dictionary.
        /// </summary>
        public int ItemCount
        {
            get
            {
                return this.items.Count;
            }
        }

        /// <summary>
        /// Enumerates all the keys in the group dictionary.
        /// </summary>
        public IEnumerable<string> GroupKeys
        {
            get
            {
                foreach (string key in this.groups.Keys)
                {
                    yield return key;
                }
            }
        }

        /// <summary>
        /// Enumerates all the keys in the item dictionary.
        /// </summary>
        public IEnumerable<string> ItemKeys
        {
            get
            {
                foreach (string key in this.items.Keys)
                {
                    yield return key;
                }
            }
        }

        /// <summary>
        /// Enumerates all the keys in the group dictionary.
        /// </summary>
        public IEnumerable<List<string>> GroupValues
        {
            get
            {
                foreach (List<string> groupValue in this.groups.Values)
                {
                    yield return groupValue;
                }
            }
        }

        /// <summary>
        /// Enumerates all the keys in the item dictionary.
        /// </summary>
        public IEnumerable<object> ItemValues
        {
            get
            {
                foreach (object value in this.items.Values)
                {
                    yield return value;
                }
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// This method protects data that the taxonomy marks as High Impact.
        /// </summary>
        /// <param name="key">The key of the data, must be validated by the caller.</param>
        /// <param name="value">The value to protect, must be validated by the caller.</param>
        /// <returns>The original value, or an adapter around the encrypted serialized version of the data.</returns>
        /// <remarks>Data that is not serializable remains unencrypted, any failure to serialize or encrypt the data returns the data as is.
        /// When considering in-memory protection, Unknown classification results in no encryption so we rely mostly on PE classifications for determining HBI.</remarks>
        private object ProtectData(string key, object value)
        {
            // key cannot be null, empty or whitespaces, verified in calling context, no need for arg validation
            // value cannot be null, verified in calling context, no need for arg validation
            if (!value.GetType().IsSerializable)
            {
                // cannot serialize this type of data, do not attempt to encrypt, return as is
                // This is a shallow test (could be aggregating non-serializable data), in this case, we will get exception below
                return value;
            }

            // getting the classification from the taxonomy chain informs whether or not we encrypt in-memory
            switch (TaxonomyChain.AuthoritativeInstance.GetClassification(key))
            {
                case TaxonomyClassification.HighImpact:
                    // processing below switch block
                    break;

                // For Internal and LowImpact data, we return the data directly
                case TaxonomyClassification.Internal:
                case TaxonomyClassification.LowImpact:
                case TaxonomyClassification.Unknown:
                default:
                    return value;
            }

            try
            {
                // Convert the key to upper case since entropy generation depends on the key casing, and workflow context keys are case insensitive
                return BinarySerializationAdapter.CreateAdapter(data => EncryptionAdapter.CreateAdapter(this.Encryptor, key.ToUpperInvariant(), data), value);
            }
            catch (SerializationException)
            {
                // nothing to log, nothing to do (checked with Muhammad)
            }
            catch (CryptographicException)
            {
                // nothing to log, nothing to do (checked with Muhammad)
            }
            catch (SecurityException)
            {
                // nothing to log, nothing to do (checked with Muhammad)
            }

            // serialization or encryption failed, returning original data
            return value;
        }

        /// <summary>
        /// This method unwraps the encrypted data if necessary.
        /// </summary>
        /// <param name="key">The key of the data, must be validated by the caller.</param>
        /// <param name="data">The adapter wrapped data or the original data, must be validated by the caller.</param>
        /// <returns>The decrypted data, if it was encrypted, or the original data otherwise.  May return null upon exception handling.</returns>
        /// <remarks>The data is typecast to IContextElement for decryption and deserialization, failure to cast returns the original data.
        /// Serialization or decryption failures are not recoverable, so the exception is swallowed and null is returned.</remarks>
        private object UnprotectData(string key, object data)
        {
            // key cannot be null, empty or whitespaces, verified in calling context, no need for arg validation
            // value cannot be null, verified in calling context, no need for arg validation
            ISerializationAdapter element = data as ISerializationAdapter;

            if (element == null)
            {
                // cannot infer context element, then this is direct data
                return data;
            }

            try
            {
                // Convert the key to upper case since entropy generation depends on the key casing, and workflow context keys are case insensitive
                return element.GetData(adapter => adapter.GetData(this.Encryptor, key.ToUpperInvariant()));
            }
            catch (SerializationException)
            {
                // nothing to log, nothing to do (checked with Muhammad)
            }
            catch (CryptographicException)
            {
                // nothing to log, nothing to do (checked with Muhammad)
            }
            catch (SecurityException)
            {
                // nothing to log, nothing to do (checked with Muhammad)
            }

            // unable to extract actual data, caller will be responsible for determining appropriate reaction
            return null;
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Clears the workflow context inner collections.
        /// </summary>
        public void Clear()
        {
            this.items.Clear();
            this.groups.Clear();
        }

        /// <summary>
        /// Setting value to container for specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <param name="value">The value.</param>
        /// <param name="groupName">Group name value</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace and DefaultGroupName is null.</exception>
        public void Add(string key, object value, string groupName = null)
        {
            // Check group name for null
            if (string.IsNullOrWhiteSpace(groupName))
            {
                // Check DefaultGroupName for null
                if (string.IsNullOrWhiteSpace(DefaultGroupName))
                {
                    throw new ArgumentNullException("groupName", "GroupName and DefaultGroupName cannot be empty");
                }
                groupName = DefaultGroupName;
            }

            // Check key for null
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException("key", "Value key cannot be empty");
            }

            // Check key for null
            if (value == null)
            {
                throw new ArgumentNullException("value", string.Format(CultureInfo.InvariantCulture, "Object cannot be null for key {0}", key));
            }

            AddToGroup(groupName, key);
            Remove(key);

            items.Add(key, this.ProtectData(key, value));
        }

        /// <summary>
        /// Adds the specified key to the group.
        /// </summary>
        public void AddToGroup(string groupName, string key)
        {
            List<string> keyList = null;

            groups.TryGetValue(groupName, out keyList);

            // let's guarantee keyList never null and properly bound to group name
            if (keyList == null)
            {
                keyList = new List<string>();
                groups[groupName] = keyList;
            }

            // Add only if the keyList does not contain the mentioned key
            if (!keyList.Contains(key, StringComparer.OrdinalIgnoreCase))
            {
                keyList.Add(key);
            }
        }

        /// <summary>
        /// Delete entry for specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>True - if key is found. False - if key is not found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        public bool Remove(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException("key", "Key cannot be empty");
            }
            if (!items.ContainsKey(key)) return false;

            items.Remove(key);
            return true;
        }

        /// <summary>
        /// Deletes all entries by specific group
        /// </summary>
        /// <param name="groupName">Group name to delete</param>
        /// <returns>
        /// True - if key is found. False - if key is not found.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace.</exception>
        public bool RemoveGroup(string groupName)
        {
            if (string.IsNullOrWhiteSpace(groupName))
            {
                throw new ArgumentNullException("groupName", "Group name cannot be null or empty");
            }
            if (!groups.ContainsKey(groupName)) return false;

            List<string> keyList = groups[groupName];
            if (keyList == null || keyList.Count == 0)
                return false;


            while (keyList.Count > 0)
            {
                string key = keyList.First();
                Remove(key);
                keyList.Remove(key);
            }

            return true;
        }

        /// <summary>
        /// Get a value from container by specific key
        /// </summary>
        /// <typeparam name="T">Expected instance type</typeparam>
        /// <param name="key">Key string value</param>
        /// <returns>
        /// Restored object from container
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        public T Get<T>(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException("key", "Key cannot be empty");
            }

            try
            {
                return (T)this.UnprotectData(key, items[key]);
            }
            catch
            {
                return default(T);
            }
        }

        /// <summary>
        /// Get a value from container by specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>
        /// restored value as an object
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        public object Get(string key)
        {
            // Checking parameters
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException("key", "Key cannot be empty");
            }

            // return object
            if (items.ContainsKey(key))
            {
                return this.UnprotectData(key, items[key]);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Get the type of a value from container by specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>
        /// The type of the value, or null if the key is not found.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>      
        public Type GetValueType(string key)
        {
            // Checking parameters
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException("key", "Key cannot be empty");
            }

            object storedValue;
            if (this.items.TryGetValue(key, out storedValue))
            {
                ISerializationAdapter adapter = storedValue as ISerializationAdapter;

                if (adapter == null)
                {
                    return storedValue.GetType();
                }
                else
                {
                    return adapter.DataType;
                }
            }

            return null;
        }

        /// <summary>
        /// Checks presence of specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>
        /// True - if key is found. False - if key is not found.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        public bool Contains(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException("key", "Key cannot be empty");
            }

            return items.ContainsKey(key);
        }

        /// <summary>
        /// Gets All the key-Values in the group.
        /// </summary>
        /// <param name="groupName">Name of the group.</param>
        /// <returns>
        /// Items belonging to a group.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace.</exception>
        public Dictionary<string, object> GetGroup(string groupName)
        {
            // Check groupName for null
            if (string.IsNullOrWhiteSpace(groupName))
            {
                throw new ArgumentNullException("groupName", "Group name cannot be null or empty");
            }

            Dictionary<string, object> temp = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            if (!groups.ContainsKey(groupName))
            {
                return temp;
            }

            List<string> keyList = groups[groupName];
            if (keyList == null || keyList.Count == 0)
            {
                return temp;
            }


            foreach (var key in keyList)
            {
                object value = Get(key);
                if (value != null)
                {
                    temp[key] = value;
                }
            }

            return temp;
        }

        /// <summary>
        /// Gets All the item keys in the group.
        /// </summary>
        /// <param name="groupName">Name of the group.</param>
        /// <returns>
        /// Items keys belonging to a group.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace.</exception>
        public List<string> GetGroupItemKeys(string groupName)
        {
            // Check groupName for null
            if (string.IsNullOrWhiteSpace(groupName))
            {
                throw new ArgumentNullException("groupName", "Group name cannot be null or empty");
            }

            List<string> result;
            if (this.groups.TryGetValue(groupName, out result))
            {
                return result;
            }

            return new List<string>();
        }

        #endregion

        #region ISerializable Methods

        #region Serialization Constants

        private const string ContextIdFieldName = "ContextId";
        private const string DefaultGroupFieldName = "DefaultGroup";
        private const string GroupsFieldName = "GroupData";
        private const string ItemsFieldName = "ItemsData";
        private const string EncryptorFieldName = "Encryptor";

        #endregion

        /// <summary>
        /// This constructor is for DeSerialization
        /// </summary>
        /// <param name="info">The System.Runtime.Serialization.SerializationInfo to populate data from.</param>
        /// <param name="context">The source (see System.Runtime.Serialization.StreamingContext) for this serialization.</param>
        protected WorkflowContext(SerializationInfo info, StreamingContext context)
        {
            this.Id = (Guid)info.GetValue(WorkflowContext.ContextIdFieldName, typeof(Guid));
            this.defaultGroupName = info.GetString(WorkflowContext.DefaultGroupFieldName);

            byte[] encryptorData = (byte[])info.GetValue(WorkflowContext.EncryptorFieldName, typeof(byte[]));
            this.encryptor = WorkflowContext.PostDeserialize<ISerializableDataEncryptor>(encryptorData);

            byte[] groupData = (byte[])info.GetValue(WorkflowContext.GroupsFieldName, typeof(byte[]));
            this.groups = WorkflowContext.PostDeserialize<Dictionary<string, List<string>>>(groupData);

            byte[] itemsData = (byte[])info.GetValue(WorkflowContext.ItemsFieldName, typeof(byte[]));
            this.items = WorkflowContext.PostDeserialize<Dictionary<string, object>>(itemsData);
        }

        /// <summary>
        /// Populates a System.Runtime.Serialization.SerializationInfo with the data needed to serialize the target object.
        /// This does NOT restore the encryptor!
        /// </summary>
        /// <param name="info">The System.Runtime.Serialization.SerializationInfo to populate with data.</param>
        /// <param name="context">The destination (see System.Runtime.Serialization.StreamingContext) for this serialization.</param>
        /// <exception cref="System.Security.SecurityException">The caller does not have the required permission.</exception>
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.AddValue(WorkflowContext.ContextIdFieldName, this.Id);
            info.AddValue(WorkflowContext.DefaultGroupFieldName, this.defaultGroupName);

            byte[] encryptorData = WorkflowContext.PreSerialize<ISerializableDataEncryptor>(this.encryptor);
            info.AddValue(WorkflowContext.EncryptorFieldName, encryptorData);

            byte[] groupData = WorkflowContext.PreSerialize<Dictionary<string, List<string>>>(this.groups);
            info.AddValue(WorkflowContext.GroupsFieldName, groupData);

            byte[] itemsData = WorkflowContext.PreSerialize<Dictionary<string, object>>(this.items);
            info.AddValue(WorkflowContext.ItemsFieldName, itemsData);
        }

        private static byte[] PreSerialize<T>(T dictionary)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                WorkflowContext.DictionaryFormatter.Serialize(stream, dictionary);
                stream.Position = 0;
                return stream.ToArray();
            }
        }

        private static T PostDeserialize<T>(byte[] data)
        {
            using (MemoryStream stream = new MemoryStream(data))
            {
                stream.Position = 0;
                return (T)WorkflowContext.DictionaryFormatter.Deserialize(stream);
            }
        }

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>true if the current object is equal to the other parameter; otherwise, false.</returns>
        /// <remarks>Deep comparison of workflow context is not really possible and fairly costly as is.
        /// Production code should avoid using this method.
        /// Test code should supplement with data equality that is meaningful in context for each key name.</remarks>
        bool IEquatable<WorkflowContext>.Equals(WorkflowContext other)
        {
            if (other == null)
            {
                return false;
            }

            if (object.ReferenceEquals(this, other))
            {
                return true;
            }

            if (!this.DefaultGroupName.Equals(other.DefaultGroupName, StringComparison.Ordinal))
            {
                return false;
            }

            if (!this.Id.Equals(other.Id))
            {
                return false;
            }

            // no good way to compare encryptors
            if (!this.Encryptor.GetType().Equals(other.Encryptor.GetType()))
            {
                return false;
            }

            // no good way to compare dictionaries

            // start with group names
            if (!WorkflowContext.CompareStringLists(this.groups.Keys, other.groups.Keys))
            {
                return false;
            }

            // check keys for every group
            foreach (string groupName in this.GroupKeys)
            {
                if (!WorkflowContext.CompareStringLists(this.GetGroupItemKeys(groupName), other.GetGroupItemKeys(groupName)))
                {
                    return false;
                }
            }

            // check item keys
            if (!WorkflowContext.CompareStringLists(this.items.Keys, other.items.Keys))
            {
                return false;
            }

            // especially difficult to check object vs object, especially since protected data do not necessarily produce the same ciphers for the same encryptor
            foreach (string keyName in this.ItemKeys)
            {
                object thisValue = this[keyName];
                object otherValue = other[keyName];

                if (!string.Equals(thisValue.ToString(), otherValue.ToString(), StringComparison.Ordinal))
                {
                    return false;
                }
            }

            // not truly ... but as good as we can verify in this context
            return true;
        }

        private static bool CompareStringLists(ICollection<string> localList, ICollection<string> otherList)
        {
            if (localList.Count != otherList.Count)
            {
                return false;
            }

            return localList.OrderBy(s => s, StringComparer.Ordinal).Zip(otherList.OrderBy(s => s, StringComparer.Ordinal), (s1, s2) => new { s1, s2 }).All(p => String.Equals(p.s1, p.s2, StringComparison.Ordinal));
        }

        #endregion
    }
}
