# X25519 in C#
A simple library based on [Golang's Curve25519](https://godoc.org/golang.org/x/crypto/curve25519) library.
## Features
* Easy to use front end
* Completely re written the Golang's crypto library in C#
* Nearly fast (about 3000 Keys and Agreements/s)
* Universal library with .Net Standard (You can also use this library anywhere in .Net (Read more below)
## Install
Use Nuget
```
Install-Package Easy-X25519
```
[Link](https://www.nuget.org/packages/Easy-X25519) to library on Nuget
## Usage
### Key Generation
```csharp
var alice = X25519KeyAgreement.GenerateKeyPair();
```
In this example, alice is `X25519KeyPair` struct that contains public key and private key as 32 byte length byte arrays.
### Key Agreement
```csharp
// generate keys
var alice = X25519KeyAgreement.GenerateKeyPair();
var bob = X25519KeyAgreement.GenerateKeyPair();
// generate shared secret
var shared1 = X25519KeyAgreement.Agreement(alice.PrivateKey, bob.PublicKey);
var shared2 = X25519KeyAgreement.Agreement(bob.PrivateKey, alice.PublicKey);
// now the shared1 and shared2 must be same
```
## Use in older versions of .Net
This library is built with .Net Standard 2; Means that minimum frameworks are .Net Core 2 and .Net framework 4.6.1. [Full list](https://docs.microsoft.com/en-us/dotnet/standard/net-standard#net-implementation-support). You might want to use this library in .Net 2. It's easy to make this library in earlier version of .Net

**Note**: Due to usage of [RNGCryptoServiceProvider](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rngcryptoserviceprovider?view=netframework-4.8) this library is not compatible with .Net Core 1.X.

Here are steps to include this library in your project:
1. At first copy `Internal.cs` and `X25519.cs` from [here](https://github.com/HirbodBehnam/X25519-CSharp/tree/master/X25519) into your project.
2. If you are using .Net Framework 4 or lower, you will get an error because [IReadonlyList](https://docs.microsoft.com/en-us/dotnet/api/system.collections.generic.ireadonlylist-1?view=netframework-4.8) is available since .Net framework 4.5. To fix this problem, just change `IReadOnlyList<byte>` in `Internal.cs` to `byte[]`. This should fix the problem.
3. Use the library
## Benchmarks
These benchmarks are done with .Net Core 3.1 on Intel-i7 4790K 4.0GHz.
```
Full key agreement done in 00:00:00.0093703
Key generation done in 00:00:00.3615465. That is about 2770 keys/sec
Key agreements done in 00:00:00.2800316. That is about 3571 agreement/sec
```
I also benchmarked the [curve25519_generic](https://github.com/golang/crypto/blob/master/curve25519/curve25519_generic.go) (not the assembly one) and this library is about twice slower than Golang. Golang key agreement was about 6625 agreement/s.