// <copyright file="EncryptionTest.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2023 Visualisierungsinstitut der Universität Stuttgart. Alle Rechte vorbehalten.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Visus.DataProtection;


namespace Crypto {

    [TestClass]
    public class EncryptionTest {

        [TestMethod]
        public void EncryptDecryptRoundTrip() {
            var config = new DataProtectionConfiguration();
            config.DatabaseKey = "q45knelfjasldfkjaherltkqu43lq345asdf5";

            var expected = "Das ist ein Test";
            var encrypted = config.Protect(expected);
            var actual = config.Unprotect(encrypted);
            Assert.AreEqual(expected, actual, "Encryption round trip with random IV.");
        }

        [TestMethod]
        public void GlobalIvOverride() {
            var config = new DataProtectionConfiguration();
            config.DatabaseKey = "356tjk2l3rt2p6erfwerg254t";
            config.InitialisationVector = "q4tq3rgwefgwrgwreg";

            var expected = "Das ist ein Test";
            var encrypted = config.Protect(expected);
            var actual = config.Unprotect(encrypted);
            Assert.AreEqual(expected, actual, "Encryption round trip with global IV.");
        }

        [TestMethod]
        public void IvOverride() {
            var config = new DataProtectionConfiguration();
            config.DatabaseKey = "356tjk2l3rt2p6erfwerg254t";
            var iv = "4534lktnlkjrfbqrgdfg";

            var expected = "Das ist ein Test";
            var encrypted = config.Protect(expected, iv);
            var actual = config.Unprotect(encrypted, iv);
            Assert.AreEqual(expected, actual, "Encryption round trip with deterministic IV.");
        }
    }
}
