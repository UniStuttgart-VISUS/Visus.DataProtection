// <copyright file="DataProtection.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2023 Visualisierungsinstitut der Universität Stuttgart. Alle Rechte vorbehalten.
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
        /// Gets or sets the number of iterations performed during key
        /// derivation.
        /// </summary>
        public int Iterations { get; set; } = 10000;

        /// <summary>
        /// Gets or sets the directory where the encryption keys should be
        /// persisted.
        /// </summary>
        /// <remarks>
        /// If not specified (<c>null</c>), the default mechanism for the
        /// platform will be used, which might be an in-memory storage that
        /// could make sessions to work incorrectly.
        /// </remarks>
        public string KeyStorage { get; set; }
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

                if (!string.IsNullOrWhiteSpace(ivOverride)) {
                    // Use the specified string to generate the IV.
                    this.OverrideIV(aes, ivOverride);

                } else {
                    // Add IV to the output as we need that for decrypting. This
                    // solution is semi-hot, but the alternative would have been
                    // using the same IV for everything and hard code it in the
                    // software, which would be even more unsafe.
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

                if (ivOverride != null) {
                    // Use the user-defined IV.
                    this.OverrideIV(aes, ivOverride);
                } else {
                    // Obtain the IV from the data. Note: The IV property
                    // returns a f*** deep copy, so we need to read that first
                    // and then set it, because otherwise, we would copy the IV
                    // into a temporary buffer that is never used.
                    var iv = new byte[aes.IV.Length];
                    ms.Read(iv);
                    aes.IV = iv;
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
        private void OverrideIV(Aes aes, string iv) {
            Contract.Assert(iv != null);
            aes.IV = KeyDerivation.Pbkdf2(
                iv,
                Encoding.UTF8.GetBytes(nameof(iv)),
                KeyDerivationPrf.HMACSHA512,
                this.Iterations,
                aes.IV.Length);
        }
        #endregion
    }
}
