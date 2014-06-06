using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CommonWorkflow.WorkFlowContext
{
    /// <summary>
    /// Interface represents a oasp workflow context object
    /// </summary>
    public interface IWorkflowContext
    {
        /// <summary>
        /// Gets or sets and Sets context ID
        /// </summary>
        Guid Id { get; set; }

        /// <summary>
        /// Gets or sets the default group name for the Items.Add.
        /// </summary>
        /// <value>
        /// The group name.
        /// </value>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null or whitespace.</exception>
        string DefaultGroupName { get; set; }

        /// <summary>
        /// Indexer access
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns> value as an object</returns>
        object this[string key] { get; set; }

        /// <summary>
        /// Gets the count of the Group dictionary.
        /// </summary>
        int GroupCount { get; }

        /// <summary>
        /// Gets the count of the Item dictionary.
        /// </summary>
        int ItemCount { get; }

        /// <summary>
        /// Enumerates all the keys in the group dictionary.
        /// </summary>
        IEnumerable<string> GroupKeys { get; }

        /// <summary>
        /// Enumerates all the keys in the item dictionary.
        /// </summary>
        IEnumerable<string> ItemKeys { get; }

        /// <summary>
        /// Enumerates all the keys in the group dictionary.
        /// </summary>
        IEnumerable<List<string>> GroupValues { get; }

        /// <summary>
        /// Enumerates all the keys in the item dictionary.
        /// </summary>
        IEnumerable<object> ItemValues { get; }

        /// <summary>
        /// Clears the workflow context inner collections.
        /// </summary>
        void Clear();

        /// <summary>
        /// Setting value to container for specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <param name="value">The value.</param>
        /// <param name="groupName">Group name value</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace and DefaultGroupName is null.</exception>
        void Add(string key, object value, string groupName = null);

        /// <summary>
        /// Adds the specified key to the group.
        /// </summary>
        void AddToGroup(string groupName, string key);

        /// <summary>
        /// Checks presence of specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>Presence boolean response</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        bool Contains(string key);

        /// <summary>
        /// Service function to deliver an object
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>restored value as an object</returns>
        /// <remarks>Returns default when object not found.</remarks>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        object Get(string key);

        /// <summary>
        /// Get a value from container by specific key
        /// </summary>
        /// <typeparam name="T">Expected instance type</typeparam>
        /// <param name="key">Key string value</param>
        /// <returns>Restored object from container</returns>
        /// <remarks>Returns default when object not found.</remarks>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        T Get<T>(string key);

        /// <summary>
        /// Get the type of a value from container by specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>
        /// The type of the value, or null if the key is not found.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>      
        Type GetValueType(string key);

        /// <summary>
        /// Gets All the key-Values in the group.
        /// </summary>
        /// <param name="groupName">Name of the group.</param>
        /// <returns>Items belonging to a group.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace.</exception>
        Dictionary<string, object> GetGroup(string groupName);/// <summary>
        
        /// Gets All the item keys in the group.
        /// </summary>
        /// <param name="groupName">Name of the group.</param>
        /// <returns>
        /// Items keys belonging to a group.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace.</exception>
        List<string> GetGroupItemKeys(string groupName);

        /// <summary>
        /// Delete entry for specific key
        /// </summary>
        /// <param name="key">Key string value</param>
        /// <returns>True - if key is found. False - if key is not found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null or whitespace.</exception>
        bool Remove(string key);

        /// <summary>
        /// Removes the group.
        /// </summary>
        /// <param name="groupName">Name of the group.</param>
        /// <returns>True - if key is found. False - if key is not found.</returns>
        /// <remarks>Removes a key even if it exists in multiple groups.</remarks>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="groupName"/> is null or whitespace.</exception>
        bool RemoveGroup(string groupName);
    }
}
