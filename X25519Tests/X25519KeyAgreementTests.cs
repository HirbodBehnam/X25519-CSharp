using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace X25519.Tests
{
    [TestClass]
    public class X25519KeyAgreementTests
    {
        [TestMethod]
        public void GenerateTest()
        {
            X25519KeyAgreement.GenerateKeyPair();
        }
        [TestMethod]
        public void AgreementTest()
        {
            // generate keys
            var k1 = X25519KeyAgreement.GenerateKeyPair();
            var k2 = X25519KeyAgreement.GenerateKeyPair();

            // calculate secrets
            var shared1 = X25519KeyAgreement.Agreement(k1.PrivateKey, k2.PublicKey);
            var shared2 = X25519KeyAgreement.Agreement(k2.PrivateKey, k1.PublicKey);

            // check if shared1 and 2 are same
            Assert.IsTrue(shared1.SequenceEqual(shared2));
        }
        [TestMethod]
        public void HugeAgreementTest()
        {
            const int rounds = 1000;
            for (int i = 0; i < rounds; i++)
            {
                // generate keys
                var k1 = X25519KeyAgreement.GenerateKeyPair();
                var k2 = X25519KeyAgreement.GenerateKeyPair();

                // calculate secrets
                var shared1 = X25519KeyAgreement.Agreement(k1.PrivateKey, k2.PublicKey);
                var shared2 = X25519KeyAgreement.Agreement(k2.PrivateKey, k1.PublicKey);

                // check if shared1 and 2 are same
                if(!shared1.SequenceEqual(shared2))
                    Assert.Fail($"Two shared secrets are not equal:\nk1:{k1.PrivateKey} , {k1.PublicKey}" +
                                $"\nk2: {k2.PrivateKey} , {k2.PublicKey}");
            }
        }
        [TestMethod]
        public void GenerateKeyFromPrivateKeyTest()
        {
            var key = X25519KeyAgreement.GenerateKeyPair();
            var newKey = X25519KeyAgreement.GenerateKeyFromPrivateKey(key.PrivateKey);
            Assert.IsTrue(key.PublicKey.SequenceEqual(newKey.PublicKey));
        }
        [TestMethod]
        public void GenerateKeyFromPrivateKeyTest2()
        {
            // predefined values
            var key1 = X25519KeyAgreement.GenerateKeyFromPrivateKey(Convert.FromBase64String("sECe8YYQT/bODurKruM8QpGFBTahurW8GqxFL+AYiW8="));
            var key2 = X25519KeyAgreement.GenerateKeyFromPrivateKey(Convert.FromBase64String("wAidyKs9iF+KA1cgBxa1rMtPwemOLFHqSIe5nkVRN2o="));
            const string secret = "dbfEcOMjYactMkh33DRhg0h1VCbmhxoWt6AR3rp6000=";
            // do the agreement
            string secret1 = Convert.ToBase64String(X25519KeyAgreement.Agreement(key1.PrivateKey, key2.PublicKey));
            string secret2 = Convert.ToBase64String(X25519KeyAgreement.Agreement(key2.PrivateKey, key1.PublicKey));
            if(secret1 != secret2)
                Assert.Fail("Secrets does not match");
            // check the final secret
            Assert.AreEqual(secret,secret1);
        }

        [TestMethod]
        public void GenerateKeyFromPrivateKeyTest3()
        {
            var priv = Convert.FromBase64String("aF9hmPSeJfKvjPam++gl7MRIQydQQu2Jdee8zOTX+lY=");
            var pub = Convert.FromBase64String("FTM52WXsEjj5hBY53RTUFmG2qUwzZxPRJdYs9lu/y3M=");
            var key = X25519KeyAgreement.GenerateKeyFromPrivateKey(priv);
            Assert.IsTrue(key.PublicKey.SequenceEqual(pub));
        }
    }
}