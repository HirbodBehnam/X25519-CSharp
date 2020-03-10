using System;
using System.Diagnostics;
using X25519;

namespace Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            // the number of tests
            const int tests = 1000;
            Stopwatch stopwatch = new Stopwatch();
            // simple key agreement
            {
                stopwatch.Start();
                // generate keys
                var k1 = X25519KeyAgreement.GenerateKeyPair();
                var k2 = X25519KeyAgreement.GenerateKeyPair();

                // generate shared secret
                var shared1 = X25519KeyAgreement.Agreement(k1.PrivateKey, k2.PublicKey);
                var shared2 = X25519KeyAgreement.Agreement(k2.PrivateKey, k1.PublicKey);
                stopwatch.Stop();
                // print them to make sure they are identical
                Console.WriteLine(Convert.ToBase64String(shared1));
                Console.WriteLine(Convert.ToBase64String(shared2));
                Console.WriteLine($"Full key agreement done in {stopwatch.Elapsed}");
            }
            stopwatch.Reset();
            // benchmark key generation
            {
                X25519KeyPair key;
                stopwatch.Start();
                for (int i = 0; i < tests; i++)
                    key = X25519KeyAgreement.GenerateKeyPair();
                stopwatch.Stop();
                Console.WriteLine($"Key generation done in {stopwatch.Elapsed}. That is about " +
                                  $"{Math.Round((double)tests/stopwatch.Elapsed.Milliseconds * 1000)} keys/sec");
            }
            stopwatch.Reset();
            // benchmark agreement
            {
                X25519KeyPair[] alice = new X25519KeyPair[tests];
                X25519KeyPair[] bob = new X25519KeyPair[tests];
                // I want to benchmark key agreement not key generation
                for (int i = 0; i < tests; i++)
                {
                    alice[i] = X25519KeyAgreement.GenerateKeyPair();
                    bob[i] = X25519KeyAgreement.GenerateKeyPair();
                }
                stopwatch.Start();
                for (int i = 0; i < tests; i++)
                    X25519KeyAgreement.Agreement(alice[i].PrivateKey, bob[i].PublicKey);
                stopwatch.Stop();
                Console.WriteLine($"Key agreements done in {stopwatch.Elapsed}. That is about " +
                                  $"{Math.Round((double)tests/stopwatch.Elapsed.Milliseconds * 1000)} agreement/sec");
                stopwatch.Reset();
            }
        }
    }
}
