using System;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace ConsoleApplication1
{
    static class ECCEncryption
    {
        private static readonly X9ECParameters Curve = ECNamedCurveTable.GetByName("secp256r1");

        private static readonly ECDomainParameters DomainParams =
            new ECDomainParameters(Curve.Curve, Curve.G, Curve.N, Curve.H);
        
        public static BigInteger GetPrivateKey(string passphrase)
        {
            var sha256 = new Sha256Digest();
            byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            byte[] hash = new byte[sha256.GetDigestSize()];
            sha256.BlockUpdate(passphraseBytes, 0, passphraseBytes.Length);
            sha256.DoFinal(hash, 0);

            var secureRandom = new SecureRandom(new DigestRandomGenerator(sha256));
            var privateKey = new BigInteger(256, secureRandom);
            while (privateKey.CompareTo(DomainParams.N) >= 0 || privateKey.Equals(BigInteger.Zero))
            {
                privateKey = new BigInteger(256, secureRandom);
            }
            
            return privateKey;
        }
        
        public static BigInteger GetPublicKey(BigInteger privateKey)
        {
            ECPoint publicKeyPoint = Curve.G.Multiply(privateKey);
            byte[] compressedPublicKey = publicKeyPoint.GetEncoded(true);
            BigInteger publicKeyBigInt = new BigInteger(1, compressedPublicKey);
            return publicKeyBigInt;
        }
        
        public static byte[] Encrypt(string message, BigInteger publicKey)
        {
            ECPublicKeyParameters publicKeyParameters = GetPublicKeyParam(publicKey);
            BigInteger privateKey = GetPrivateKey("");
            ECPrivateKeyParameters privateKeyParameters = GetPrivateKeyParam(privateKey);
            
            BigInteger sharedSecret = GetSecret(privateKeyParameters, publicKeyParameters);
            byte[] keyBytes = sharedSecret.ToByteArrayUnsigned();
            byte[] ivBytes = new byte[16];
            Array.Copy(keyBytes, keyBytes.Length - 16, ivBytes, 0, 16);

            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            cipher.Init(true, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] encryptedBytes = cipher.DoFinal(messageBytes);

            return encryptedBytes;
        }
        
        public static string Decrypt(byte[] encryptedMessage, BigInteger privateKey)
        {
            ECPrivateKeyParameters privateKeyParameters = GetPrivateKeyParam(privateKey);
            BigInteger publicKey = GetPublicKey(privateKey);
            ECPublicKeyParameters publicKeyParameters = GetPublicKeyParam(publicKey);
            
            BigInteger sharedSecret = GetSecret(privateKeyParameters, publicKeyParameters);

            byte[] keyBytes = sharedSecret.ToByteArrayUnsigned();
            byte[] ivBytes = new byte[16];
            Array.Copy(keyBytes, keyBytes.Length - 16, ivBytes, 0, 16);

            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            cipher.Init(false, new ParametersWithIV(new KeyParameter(keyBytes), ivBytes));
            byte[] decryptedBytes = cipher.DoFinal(encryptedMessage);

            return Encoding.UTF8.GetString(decryptedBytes);
        }
        
        private static ECPublicKeyParameters GetPublicKeyParam(BigInteger publicKey)
        {
            ECPoint publicKeyPoint = Curve.Curve.DecodePoint(publicKey.ToByteArrayUnsigned());
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(publicKeyPoint, DomainParams);
            return publicKeyParameters;
        }

        private static ECPrivateKeyParameters GetPrivateKeyParam(BigInteger privateKey)
        {
            var privateKeyParameters = new ECPrivateKeyParameters(privateKey, DomainParams);
            return privateKeyParameters;
        }
        
        private static BigInteger GetSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
        {
            var agreement = new ECDHBasicAgreement();
            agreement.Init(privateKey);
            return agreement.CalculateAgreement(publicKey);
        }
        
    }

    internal class Program
    {
        public static void Main(string[] args)
        {
            var privateKey = ECCEncryption.GetPrivateKey("passphrase");
            Console.WriteLine(privateKey);
            
            var publicKey = ECCEncryption.GetPublicKey(privateKey);
            Console.WriteLine(publicKey);

            
            var encryptMsg = ECCEncryption.Encrypt("message", publicKey);
            var message = ECCEncryption.Decrypt(encryptMsg, privateKey, "");
            Console.WriteLine(message);
        }
    }
}