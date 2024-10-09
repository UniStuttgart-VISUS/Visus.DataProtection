// <copyright file="DataProtectionConfiguration.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2023 - 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for details.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;


namespace Visus.DataProtection {

    /// <summary>
    /// Data protection (column-level database encryption) configuration.
    /// </summary>
    /// <remarks>
    /// This class can by mapped directly to a section of the application
    /// settings, but it also implements the crypto itself, which can be
    /// added to the data context via <see cref="EntityBuilderExtensions"/>.
    /// </remarks>
    public class DataProtectionConfiguration {

        #region Public constants
        /// <summary>
        /// The recommended name of the configuration section in appsettings.
        /// </summary>
        public const string Section = "DataProtection";
        #endregion

        #region Public class methods
        /// <summary>
        /// Gets (if any) the override intialisation vector for the given
        /// property of the <typeparamref name="TEntity"/>.
        /// </summary>
        /// <typeparam name="TEntity">The entity to get the IV for.</typeparam>
        /// <param name="propertyName">The name of the property to be checked.
        /// </param>
        /// <returns>The value of <see cref="ProtectedAttribute.Searchable"/>
        /// if the designated property has such an attribute.</returns>
        public static string GetOverrideIV<TEntity>(string propertyName) {
            var prop = typeof(TEntity).GetProperty(propertyName);
            var att = prop?.GetCustomAttribute<ProtectedAttribute>();
            return att?.Searchable;
        }
        #endregion

        #region Public properties
        /// <summary>
        /// Gets or sets the encryption key used for encrypting personal data.
        /// </summary>
        public string DatabaseKey { get; set; }

        /// <summary>
        /// Gets or sets the global initialisation vector used for AES.
        /// </summary>
        /// <remarks>
        /// <para>The actual IV will be derived using a PKDF and 
        /// <see cref="Iterations"/>.</para>
        /// <para>If this is <c>null</c>, the implementation will derive a
        /// random IV each time and embed it into the data like the salt in
        /// Unix crypt.</para>
        /// <para>You cannot change this property if the database is already
        /// in production and the implementation has written random IVs to
        /// the table. If this string is <c>null</c> or empty, the
        /// implementation uses this as the trigger to use random IVs.</para>
        /// </remarks>
        public string InitialisationVector { get; set; }

        /// <summary>
        /// Gets or sets the number of iterations performed during key
        /// derivation.
        /// </summary>
        public int Iterations { get; set; } = 10000;
        #endregion

        #region Public methods
        /// <summary>
        /// Gets a new AES instance for encrypting or decrypting personal data.
        /// </summary>
        /// <remarks>
        /// <para>The encryption key will already be set on the instance. Make
        /// sure to dispose after use.</para>
        /// </remarks>
        public Aes GetEncryptionAlgorithm() {
            var retval = Aes.Create();
            retval.KeySize = 256;
            retval.Mode = CipherMode.CBC;
            retval.Padding = PaddingMode.PKCS7;

            retval.Key = KeyDerivation.Pbkdf2(
                this.DatabaseKey,
                Encoding.UTF8.GetBytes(nameof(this.DatabaseKey)),
                KeyDerivationPrf.HMACSHA512,
                this.Iterations,
                retval.KeySize / 8);

            return retval;
        }

        /// <summary>
        /// Encrypts the given value with the configured key.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="ivOverride"></param>
        /// <returns></returns>
        public string Protect(string value, string ivOverride = null) {
            if (value != null) {
                using var aes = this.GetEncryptionAlgorithm();
                using var ms = new MemoryStream();

                if (!string.IsNullOrEmpty(ivOverride)) {
                    // Use the specified string to generate the IV.
                    this.SetIV(aes, ivOverride);

                } else if (!string.IsNullOrEmpty(this.InitialisationVector)) {
                    // Use global user-defined string for the IV.
                    this.SetIV(aes, this.InitialisationVector);

                } else {
                    // Add IV that the AES has generated for us to the output
                    // as we need that for decrypting. This solution is
                    // semi-hot ...
                    ms.Write(aes.IV, 0, aes.IV.Length);
                }

                // Encrypt the data.
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(),
                    CryptoStreamMode.Write))
                using (var sw = new StreamWriter(cs)) {
                    sw.Write(value);
                    sw.Flush();
                }

                // Convert to base64 for the database.
                value = Convert.ToBase64String(ms.ToArray());

            }
            return value;
        }

        /// <summary>
        /// Decrypts the given value using the configured key.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="ivOverride"></param>
        /// <returns></returns>
        public string Unprotect(string value, string ivOverride = null) {
            if (value != null) {
                using var aes = this.GetEncryptionAlgorithm();
                using var ms = new MemoryStream(Convert.FromBase64String(value));

                if (!string.IsNullOrEmpty(ivOverride)) {
                    // Use the user-defined IV.
                    this.SetIV(aes, ivOverride);

                } else if (!string.IsNullOrEmpty(this.InitialisationVector)) {
                    // Use global user-defined IV.
                    this.SetIV(aes, this.InitialisationVector);

                } else {
                    // Obtain the IV from the start of the data.
                    this.SetIV(aes, ms);
                }

                // Encrypt the data.
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(),
                    CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs)) {
                    return sr.ReadToEnd();
                }
            }

            return value;
        }
        #endregion

        #region Private methods
        private void SetIV(Aes aes, string iv) {
            Contract.Assert(iv != null);
            aes.IV = KeyDerivation.Pbkdf2(
                iv,
                Encoding.UTF8.GetBytes(nameof(iv)),
                KeyDerivationPrf.HMACSHA512,
                this.Iterations,
                aes.IV.Length);
        }

        private void SetIV(Aes aes, MemoryStream stream) {
            // Obtain the IV from the given stream. Note: The IV property
            // returns a f*** deep copy, so we need to read that first
            // and then set it instead of writing into the array we get from
            // a property get, because otherwise, we would copy the IV into a
            // temporary buffer that is never used.
            var iv = new byte[aes.IV.Length];
            stream.Read(iv);
            aes.IV = iv;
        }
        #endregion
    }
}
