# Visus.DataProtection

A library that adds per-column encryption (for string columns) to Entity Framework Core.

## How it works
The library must be injected when building a database model. It functions as a conversion for a property of an entity, which encrypts the data using AES when writing it and decrypts it when reading it. In order to perform the AES encryption, you need to provide an encryption key in your appsettings.json via the `DataProtectionConfiguration` options class. If you provide an initialisation vector here, this value will be used for all properties, otherwise, random IV will be created every time. 

> [!CAUTION]
> You must not change `DataProtectionConfiguration.DatabaseKey` nor `DatabaseKey.InitialisationVector` after you wrote the first data to the database or you will lose access to the data already written!

## Usage

Add a section for `DataProtectionConfiguration` in your appsettings.json. Set a `DatabaseKey`, which will be converted to an AES key via PBKDF2. You can configure the iterations via `DataProtectionConfiguration.Iterations`. The default is 10,000.
```json
"DataProtection": {
    "DatabaseKey": "Some random stuff that you should keep secret."
}
```

Add the configuration to the service collection:
```c#
builder.Services.AddOptions<DataProtectionConfiguration>()
    .Bind(config.GetSection("DataProtection"));
```

In you database context, inject `IOptions<DataProtectionConfiguration>` to get access to the cryto parameters.
```c#
public MyContext(DbContextOptions<MyContext> dbOptions,
        IOptions<DataProtectionConfiguration> dpOptions)
        : base(dbOptions) {
    this._dataProtection = dpOptions.Value;
}
```

Override `OnModelCreating` to add the encryption converter:
```c#
modelBuilder.Entity<MyEntity>(b => {
    b.AddDataProtection(this._dataProtection);
});
```

The encryption will affect all properties of `MyEntity` which have been marked with `[Protected]`:
```c#
public sealed class MyEntity {

    [Key, Column(Order = 0)]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int ID { get; set; }

    [Column(Order = 1)]
    [Protected]
    public string Secret { get; set; }

    [Column(Order = 2)]
    [Protected(Searchable = "ADFKJ$asdjb234134m.djn34änds/(gsd")]
    public string Searchable { get; set; }
}
```

Setting the `Searchable` property of the `ProtectedAttribute` forces the initialisation vector of the column to be derived from the property, even if random IVs were configured in `DataProtectionConfiguration`. This enables searching the column for exact matches, because the search string can be encrypted the same way as the data.

> [!WARNING]
> Do not copy the `Searchable` value from the example, but use your own string. If possible, to not check in the code to a public repository.
