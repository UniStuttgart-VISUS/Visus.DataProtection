// <copyright file="EntityBuilderExtensions.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2023 - 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for details.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Linq;
using System.Reflection;


namespace Visus.DataProtection {

    /// <summary>
    /// Extension methods for <see cref=""/>
    /// </summary>
    public static class EntityBuilderExtensions {

        /// <summary>
        /// Adds the <see cref="DataProtectionConverter"/> to the given entity.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to add data
        /// protection to</typeparam>
        /// <param name="builder">The type builder used to add the data
        /// protection configuration to.</param>
        /// <param name="dataProtection">The data protection configuration to be
        /// added to the entity. This instance specifies the crypto keys used to
        /// protect the annotated columns.</param>
        /// <returns><paramref name="builder"/>.</returns>
        /// <exception cref="ArgumentNullException">If any of the parameters is
        /// <c>null</c>.</exception>
        public static EntityTypeBuilder<TEntity> AddDataProtection<TEntity>(
                this EntityTypeBuilder<TEntity> builder,
                DataProtectionConfiguration dataProtection)
                where TEntity : class {
            _ = builder ?? throw new ArgumentNullException(nameof(builder));
            _ = dataProtection ?? throw new ArgumentNullException(
                nameof(dataProtection));

            if (dataProtection != null) {
                var properties = from p in typeof(TEntity).GetProperties()
                                 let a = p.GetCustomAttribute<ProtectedAttribute>()
                                 where (a != null)
                                 select new {
                                     Type = p.PropertyType,
                                     Name = p.Name,
                                     IV = a?.Searchable
                                 };

                foreach (var p in properties) {
                    if (p.Type != typeof(string)) {
                        throw new NotSupportedException(
                            Properties.Resources.ErrorNonStringColumn);

                    } else {
                        builder.Property<string>(p.Name).HasConversion(
                            v => dataProtection.Protect(v, p.IV),
                            v => dataProtection.Unprotect(v, p.IV));
                    }
                }
            }

            return builder;
        }

        /// <summary>
        /// Retrieves the <see cref="EntityTypeBuilder{TEntity}"/> from
        /// <paramref name="builder"/> and adds data projection to the
        /// specified entity <typeparamref name="TEntity"/>.
        /// </summary>
        /// <typeparam name="TEntity">The type of the entity to add data
        /// protection to</typeparam>
        /// <param name="builder">The model builder used to add the data
        /// protection configuration to.</param>
        /// <param name="dataProtection">The data protection configuration to be
        /// added to the entity. This instance specifies the crypto keys used to
        /// protect the annotated columns.</param>
        /// <returns><paramref name="builder"/>.</returns>
        /// <exception cref="ArgumentNullException">If any of the parameters is
        /// <c>null</c>.</exception>
        public static ModelBuilder AddDataProtection<TEntity>(
                this ModelBuilder builder,
                DataProtectionConfiguration dataProtection)
                where TEntity : class {
            _ = builder ?? throw new ArgumentNullException(nameof(builder));
            builder.Entity<TEntity>(b => b.AddDataProtection(dataProtection));
            return builder;
        }

    }
}
