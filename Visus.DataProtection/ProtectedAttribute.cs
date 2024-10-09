// <copyright file="ProtectedAttribute.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2023 - 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for details.
// </copyright>
// <author>Christoph Müller</author>

using System;


namespace Visus.DataProtection {

    /// <summary>
    /// An attribute for marking properties containing sensitive data that
    /// should be encrypted.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    public sealed class ProtectedAttribute : Attribute {

        /// <summary>
        /// Gets or sets a salt string that makes the field searchable as it
        /// does use this key instead of a random initialisation vector.
        /// </summary>
        /// <remarks>
        /// Setting a string here makes the encryption deterministic by removing
        /// the random initialisation vector, thus enabling the client to search
        /// the field (at least for exact matches) by encrypting the query on
        /// the client side. In contrast, the random IV makes it impossible to
        /// test a field for equality in the database as the IV changes every
        /// time the field is written.
        /// </remarks>
        public string Searchable {
            get;
            set;
        }
    }
}
