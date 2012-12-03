using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Collections;

namespace Lidgren.Network.Authentication
{
    /// <summary>
    /// Library of SRP Functions used in SRP protocol.
    /// Refs:
    /// http://srp.stanford.edu/design.html
    /// http://www.ietf.org/internet-drafts/draft-ietf-tls-srp-09.txt
    /// 
    /// Required Credit to Tom Wu for the SRP algo:
    /// "This product uses the 'Secure Remote Password' cryptographic authentication system developed by Tom Wu (tjw@CS.Stanford.EDU)."
    /// 
    /// Note: Method naming follows the SRP6 naming of variables which may be a single upper case or lower case character. This allows a reader to more easily
    /// follow the protocol at the expense of non-standard method naming convension.
    /// </summary>
    internal static partial class NetSRP
    {
        private static HashAlgorithm hashAlgo = SHA1.Create();

        // Various N's sizes in Base64. These are the supported bit sizes.  We use on 1024 bit for now, but any of the following can be used.
        // Both client and server must agree on same N and g.  As N and g are needed to generate Verifier, N and g are "fixed" after verifier creation
        // on the server (i.e. the client can not just pick a size of N).
        private const String prime1024Bit = "7q8Kua2zjdacM/gK+o/F6GByYYd1/zwLnqIxTJwlZXbWdN90luqB0zg7SBPWksbg4NXY4lC5i+SOSVwdYIna0V3H17RhVNa2zo70rWmxXUmCVZspe88YhcUp9WZmDlfsaO28PAVybMAv1Mv0l26qmv1ROP6DdkNbn8YdL8DrBuM=";
        private const String prime1536Bit = "ne88r7k5J3qx8SqGF6R7u9ulHfSZrEyAvu6pYUsZzE1fT19VbifL3lHGqUvkYHopFViQO6DQ+EOAtlW7miLo3N8CinzsZ/DQgTSxyLl5iRSbYJ4L47q2PUdUg4HbxbH8dk4/S1PdnaEVi/0+K5yM9W7fAZU5NJYn2y/VPSS3xIZldy5DfWx/jORCc0r3zLeug3wmSuOpvrh/ii/puLUpLloCH/9ekUeejOeijCRCxvMVGA+TSZojTc924/7RNfm7";
        private const String prime2048Bit = "rGvbQTJKmpvxZt5eE4lYL69ytmUZh+4H/DGSlD21YFCjcynLtKCZ7YGT4HV3Z6E91SMSq0sDMQ3Nf0ip2gT9UOgIOWntt2ewz2CVF5oWOrNmGgX71fqq6CkYqZYvC5O4Vfl5k+yXXuqoDXQK2/T/dHNZ0EHVwz6nHSgeRGsUdzvKl7Q6I/uAFna9IHpDbGSB8dK5B4cXRhpbnTLmiPh3SFRFI7UksNV9Xqd6J3XS7PoDLPvb9S+zeGFgJ5AE5Xrmr4dOcwPOUymczAQce8MI2CpWmPOo0MOCca41+Onb+7aUtcgD2J965DXeI21SX1R1m2XjcvzWjvIPpxEfnkr/cw==";
        private const String prime3072Bit = "///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhghfDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYMfbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshqZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqTrSyv//////////";
        private const String prime4096Bit = "///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhghfDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYMfbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshqZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEIARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBIHNAGkSc=";
        private const String prime6144Bit = "///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhghfDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYMfbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshqZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEIARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBIHNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XIdA/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1haxUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebcxAJP//////////";
        private const String prime8192Bit = "///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhghfDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq5RXSJhiY+gUQFXKOWoqqxC2tMxcNBFB6M6hVIavfHLpk7PuFBFjb7wqK6nFXXQYMfbOXD4Wm4eTHq/WujNsJM9cejJTgSiVhnc7j0iYa0u5r8S/6BtmKCGTYdgJzPshqZFIfKxgXeyAMu+EXV3phXWx3CYjAutlG4gjiT6B05asxQ9tb/OD9EI5LgtEgqSEIARpyPBKnh+bXiHGaEL26WyaZwycYavTiPBqUaDS2FQvaJYPpyirUTOjbu8LbBN6O+S6O/BQfvsqmKHxZR05rwF2ZspZPoJDDoiM7oYZRW+ftH2EpcM7i16+4G912IXBIHNAGkSfVsFqpk7TqmI2P3cGG/7fckKbAj030Nck0AoSSNsP6tNJ8cCbB1NyyYCZG3sl1HnY9uje9+P+UBq2eUw7l2zgvQTABrrBqU+2QJ9gxF5cnsIZaiRjaPtvrz5sU7UTObLrO1Lsb238UR+bMJUszIFFRK9evQm+49AE3jNK/WYPKAcZLkuzwMuoV0XIdA/SC185udP721V5wL0aYDIK1qEAxkAscnlnnyX++x+jzI6l6fjbMiL4PHUW3/1haxUvUB7IrQVSqzI9tfr9I4dgUzF7SD4A34KeXFe7ym+MoBqHVi7fF2nb1UKo9ih+/8OsZzLGjE9Vc2lbJ7C7yljI4f+jXbjwEaAQ+j2Y/SGDuEr8tWwt0dNbmlPkebb4RWXSjkm8S/uXkOHd8tqky34zYvsTQc7kxujvIMraNndMAdB+nv4r8R+0ldvaTa6QkZjqrY5xa5PVoNCO0dCvxyXgjjxbL451lLeP9uL78hIrZIiIuBKQDfAcT61eoGiPwxzRz/GRs6jBrS8vIhi+Dhd36nUt/osCH6HloMwPtW906Bis89bOieKZtKhP4P0T4Ld8xDuB0q2o2RZfomaAlXcFk8xzFCEaFHfmrSBld7X6hsdUQvX7nTXP682vDHs+iaDWQRvTrh5+SQAlDi0gcbNeImgAu1e44K8kZDab8Am5HlVjkR1Z36aqeMFDidlaU38gfVuiAuW5xYMmA3Zjt09///////////w==";

        #region N and g creation
        /// <summary>
        /// A large safe 1024 bit prime. All SRP arithmetic is done modulo N.
        /// See: http://www.ietf.org/internet-drafts/draft-ietf-tls-srp-09.txt
        /// </summary>
        public static readonly NetBigInteger N1024Bit = new NetBigInteger(1, Convert.FromBase64String(prime1024Bit));
        /// <summary>
        /// Generator modulo N for 1024 bit N.
        /// </summary>
        public static readonly NetBigInteger g1024Bit = NetBigInteger.Two;

        /// <summary>
        /// A large safe 1536 bit prime. All SRP arithmetic is done modulo N.
        /// </summary>
        public static readonly NetBigInteger N1536Bit = new NetBigInteger(1, Convert.FromBase64String(prime1536Bit));
        /// <summary>
        /// Generator modulo N for 1536 bit N.
        /// </summary>
        public static readonly NetBigInteger g1536Bit = NetBigInteger.Two;

        /// <summary>
        /// A large safe 2048 bit prime. All SRP arithmetic is done modulo N.
        /// </summary>
        public static readonly NetBigInteger N2048Bit = new NetBigInteger(1, Convert.FromBase64String(prime2048Bit));
        /// <summary>
        /// Generator modulo N for 2048 bit N.
        /// </summary>
        public static readonly NetBigInteger g2048Bit = NetBigInteger.Two;

        /// <summary>
        /// A large safe 3072 bit prime. All SRP arithmetic is done modulo N.
        /// </summary>
        public static readonly NetBigInteger N3072Bit = new NetBigInteger(1, Convert.FromBase64String(prime3072Bit));
        /// <summary>
        /// Generator modulo N for 3072 bit N.
        /// </summary>
        public static readonly NetBigInteger g3072Bit = NetBigInteger.ValueOf(5);

        /// <summary>
        /// A large safe 4096 bit prime. All SRP arithmetic is done modulo N.
        /// </summary>
        public static readonly NetBigInteger N4096Bit = new NetBigInteger(1, Convert.FromBase64String(prime4096Bit));
        /// <summary>
        /// Generator modulo N for 4096 bit N.
        /// </summary>
        public static readonly NetBigInteger g4096Bit = NetBigInteger.ValueOf(5);

        /// <summary>
        /// A large safe 6144 bit prime. All SRP arithmetic is done modulo N.
        /// </summary>
        public static readonly NetBigInteger N6144Bit = new NetBigInteger(1, Convert.FromBase64String(prime6144Bit));
        /// <summary>
        /// Generator modulo N for 6144 bit N.
        /// </summary>
        public static readonly NetBigInteger g6144Bit = NetBigInteger.ValueOf(5);

        /// <summary>
        /// A large safe 8192 bit prime. All SRP arithmetic is done modulo N.
        /// </summary>
        public static readonly NetBigInteger N8192Bit = new NetBigInteger(1, Convert.FromBase64String(prime8192Bit));
        /// <summary>
        /// Generator modulo N for 8192 bit N.
        /// </summary>
        public static readonly NetBigInteger g8192Bit = NetBigInteger.ValueOf(5);
        #endregion

        /// <summary>
        /// Returns N and g as an out parameter based on given keySize.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="g"></param>
        /// <returns></returns>
        public static NetBigInteger GetNandG(Int32 keySize, out NetBigInteger g)
        {
            switch (keySize)
            {
                case 1024:
                    g = g1024Bit;
                    return N1024Bit;
                case 1536:
                    g = g1536Bit;
                    return N1536Bit;
                case 2048:
                    g = g2048Bit;
                    return N2048Bit;
                case 3072:
                    g = g3072Bit;
                    return N3072Bit;
                case 4096:
                    g = g4096Bit;
                    return N4096Bit;
                case 6144:
                    g = g6144Bit;
                    return N6144Bit;
                case 8192:
                    g = g8192Bit;
                    return N8192Bit;
            }
            throw new ArgumentOutOfRangeException("Invalid key size.");
        }

        /// <summary>
        /// Host stores v (password verifier) in database.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="N"></param>
        /// <param name="g"></param>
        /// <returns></returns>
        public static NetBigInteger PasswordVerifier(String userName, String password, Byte[] salt, NetBigInteger N, NetBigInteger g)
        {
            NetBigInteger x = NetSRP.Calcx(salt, userName, password);
            return NetSRP.CalcV(N, g, x);
        }

        /// <summary>
        /// Returns a - a random private value.
        /// </summary>
        /// <returns></returns>
        public static NetBigInteger Geta()
        {
            //return NetBigInteger.GenerateRandom(256);
            Byte[] random = new Byte[1024 / 8];
            NetRandom.Instance.NextBytes(random);
            return new NetBigInteger(random);
        }

        /// <summary>
        /// Returns b - a random private value.
        /// </summary>
        /// <returns></returns>
        public static NetBigInteger Getb()
        {
            //return NetBigInteger.GenerateRandom(256);
            Byte[] random = new Byte[1024 / 8];
            NetRandom.Instance.NextBytes(random);
            return new NetBigInteger(random);
        }

        /// <summary>
        /// Returns A.
        /// </summary>
        /// <param name="N"></param>
        /// <param name="g"></param>
        /// <param name="a"></param>
        /// <returns></returns>
        public static NetBigInteger CalcA(NetBigInteger N, NetBigInteger g, NetBigInteger a)
        {
            // A = g^a % N
            if (g == null)
                throw new ArgumentNullException("g");
            if (N == null)
                throw new ArgumentNullException("N");

            return g.ModPow(a, N);
        }

        /// <summary>
        /// M2 is Server's proof of K.
        /// </summary>
        /// <returns></returns>
        public static Byte[] CalcM2(NetBigInteger A, Byte[] M, Byte[] K)
        {
            // Host -> User:  H(A, M, K)
            Byte[] ABytes = A.ToByteArray();
            ArrayList al = new ArrayList();
            al.Add(ABytes);
            al.Add(M);
            al.Add(K);
            Byte[] all = NetUtility.JoinArrays(al);
            return hashAlgo.ComputeHash(all);
        }

        /// <summary>
        /// M is client's proof of K.
        /// </summary>
        /// <returns></returns>
        public static Byte[] CalcM(NetBigInteger N, NetBigInteger g, String userName, Byte[] salt, NetBigInteger A, NetBigInteger B, Byte[] K)
        {
            // User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
            Byte[] gBytes = g.ToByteArray();
            Byte[] NBytes = N.ToByteArray();
            Byte[] hg = hashAlgo.ComputeHash(gBytes);
            Byte[] hN = hashAlgo.ComputeHash(NBytes);
            Byte[] gNXorBytes = XorArrays(hN, hg);
            Byte[] userNameBytes = Encoding.UTF8.GetBytes(userName);
            Byte[] hUserNameBytes = hashAlgo.ComputeHash(userNameBytes);
            Byte[] ABytes = A.ToByteArray();
            Byte[] BBytes = B.ToByteArray();
            ArrayList al = new ArrayList();
            al.Add(gNXorBytes);
            al.Add(hUserNameBytes);
            al.Add(salt);
            al.Add(ABytes);
            al.Add(BBytes);
            al.Add(K);
            Byte[] all = NetUtility.JoinArrays(al);
            return hashAlgo.ComputeHash(all);
        }

        /// <summary>
        /// XOR two byte arrays together and returns result.  Both arrays must be same length and neither can be null.
        /// Resulting array will be same size as array1.
        /// </summary>
        /// <param name="array1"></param>
        /// <param name="array2"></param>
        /// <returns>Byte[] which is the XOR result of input arrays.</returns>
        private static Byte[] XorArrays(Byte[] array1, Byte[] array2)
        {
            if (array1 == null)
                throw new ArgumentNullException("array1");
            if (array2 == null)
                throw new ArgumentNullException("array2");
            if (array1.Length == 0)
                throw new ArgumentOutOfRangeException("array1 can not be zero length.");
            if (array1.Length != array2.Length)
                throw new ArgumentOutOfRangeException("array1.Length != array2.Length");

            Byte[] newArray = new Byte[array1.Length];
            for (int i = 0; i < array1.Length; i++)
            {
                newArray[i] = (Byte)(array1[i] ^ array2[i]);
            }
            return newArray;
        }

        /// <summary>
        /// Calculates B.
        /// </summary>
        /// <param name="N"></param>
        /// <param name="g"></param>
        /// <param name="b"></param>
        /// <param name="v"></param>
        /// <returns></returns>
        public static NetBigInteger CalcB(NetBigInteger N, NetBigInteger g, NetBigInteger b, NetBigInteger v)
        {
            //B = k*v + g^b % N
            NetBigInteger k = Calck(N, g);
            return (k.Multiply(v).Add(g.ModPow(b, N))).Mod(N);
        }

        /// <summary>
        /// Calculates u.
        /// </summary>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <returns></returns>
        public static NetBigInteger Calcu(NetBigInteger A, NetBigInteger B)
        {
            // Both:  u = SHA1(PAD(A) | PAD(B))
            Byte[] aBytes = A.ToByteArray();
            Byte[] bBytes = B.ToByteArray();
            Byte[] both = NetUtility.JoinArrays(aBytes, bBytes);
            Byte[] hash = hashAlgo.ComputeHash(both);
            return new NetBigInteger(hash);
        }

        /// <summary>
        /// Calculates k.
        /// </summary>
        /// <param name="N"></param>
        /// <param name="g"></param>
        /// <returns></returns>
        public static NetBigInteger Calck(NetBigInteger N, NetBigInteger g)
        {
            // k = SHA1(N | PAD(g)) SRP-6a
            Byte[] gBytes = g.ToByteArray();
            Byte[] NBytes = N.ToByteArray();
            Byte[] both = NetUtility.JoinArrays(NBytes, gBytes);
            Byte[] hash = hashAlgo.ComputeHash(both);
            return new NetBigInteger(hash);
        }

        /// <summary>
        /// Calculates x.
        /// </summary>
        /// <param name="salt"></param>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static NetBigInteger Calcx(Byte[] salt, String userName, String password)
        {
            // x = SHA(s + SHA(userName + ":" + password))
            Byte[] saltBytes = salt;
            Byte[] innerBytes = Encoding.UTF8.GetBytes(userName + ":" + password);
            Byte[] bytes = NetUtility.JoinArrays(saltBytes, innerBytes);
            Byte[] hash = hashAlgo.ComputeHash(bytes);
            NetBigInteger x = new NetBigInteger(hash);
            return x;
        }

        /// <summary>
        /// Calculates V.  The password verifier.
        /// </summary>
        /// <param name="N"></param>
        /// <param name="g"></param>
        /// <param name="x"></param>
        /// <returns></returns>
        public static NetBigInteger CalcV(NetBigInteger N, NetBigInteger g, NetBigInteger x)
        {
            // v = g^x % N
            return g.ModPow(x, N);
        }

        /// <summary>
        /// Calculates client's S.
        /// </summary>
        /// <param name="N"></param>
        /// <param name="g"></param>
        /// <param name="B"></param>
        /// <param name="k"></param>
        /// <param name="x"></param>
        /// <param name="a"></param>
        /// <param name="u"></param>
        /// <returns></returns>
        public static NetBigInteger CalcSClient(NetBigInteger N, NetBigInteger g, NetBigInteger B, NetBigInteger k, NetBigInteger x, NetBigInteger a, NetBigInteger u)
        {
            // <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
            // (B + (N - ((k*g.ModExp(x,N))%N))) - Do it this way.  Thanks Valery.
            NetBigInteger S = (B.Add(N.Subtract((k.Multiply(g.ModPow(x, N))).Mod(N)))).ModPow(a.Add(u.Multiply(x)), N);
            return S;
        }

        /// <summary>
        /// Calculates server's S.
        /// </summary>
        /// <param name="N"></param>
        /// <param name="A"></param>
        /// <param name="v"></param>
        /// <param name="u"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static NetBigInteger CalcSServer(NetBigInteger N, NetBigInteger A, NetBigInteger v, NetBigInteger u, NetBigInteger b)
        {
            // Host:  S = (Av^u) ^ b   (computes session key)
            NetBigInteger S = (A.Multiply(v.ModPow(u, N))).ModPow(b, N);
            return S;
        }

        /// <summary>
        /// Returns 32 byte array using SHA256 one-way hash of value S.
        /// RijndaelManaged, for example can use max key of 32 bytes directly,
        /// so this is convienent.  If you need more or less entropy, add or subtract
        /// bytes as required.  Naturally, both sides need to be able to generate the same
        /// key bytes.  It is recommended to just use the 32 bytes as returned from this
        /// method.
        /// </summary>
        /// <param name="S"></param>
        /// <returns></returns>
        public static Byte[] CalcK(NetBigInteger S)
        {
            SHA256 sha256 = SHA256.Create();
            Byte[] ba = sha256.ComputeHash(S.ToByteArray());
            return ba;
        }

        /// <summary>
        /// Returns cryptographically random salt bytes.
        /// </summary>
        /// <returns>Random Salt</returns>
        public static Byte[] GenerateSalt()
        {
            Byte[] saltBytes = new Byte[10];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(saltBytes);
            return saltBytes;
        }

        /// <summary>
        /// Create XTEA symmetrical encryption object from sessionValue
        /// </summary>
        public static NetXtea CreateEncryption(Byte[] sessionValue)
        {
            HashAlgorithm sha = hashAlgo;
            Byte[] hash = sha.ComputeHash(sessionValue);

            Byte[] key = new Byte[16];
            for (Int32 i = 0; i < 16; i++)
            {
                key[i] = hash[i];
                for (Int32 j = 1; j < hash.Length / 16; j++)
                    key[i] ^= hash[i + (j * 16)];
            }

            return new NetXtea(key);
        }

        //public static Byte[] InterleaveSHAKey(NetBigInteger S)
        //{
        //    //   The SHA_Interleave function used in SRP-SHA1 is used to generate a
        //    //   session key that is twice as long as the 160-bit output of SHA1.  To
        //    //   compute this function, remove all leading zero bytes from the input.
        //    //   If the length of the resulting string is odd, also remove the first
        //    //   byte.  Call the resulting string T.  Extract the even-numbered bytes
        //    //   into a string E and the odd-numbered bytes into a string F, i.e.
        //    //
        //    //     E = T[0] | T[2] | T[4] | ...
        //    //     F = T[1] | T[3] | T[5] | ...
        //    //
        //    //   Both E and F should be exactly half the length of T.  Hash each one
        //    //   with regular SHA1, i.e.
        //    //
        //    //     G = SHA(E)
        //    //     H = SHA(F)
        //    ArrayList al = new ArrayList(S.ToByteArray());
        //    while(true)
        //    {
        //        if ( (byte)al[0] == 0 )
        //            al.RemoveAt(0);
        //        else
        //            break;
        //    }
        //    // If Odd len, remove first element.
        //    if ( (al.Count % 2) > 0 )
        //    {
        //        al.RemoveAt(0);
        //    }
        //    int count = al.Count / 2;
        //    Byte[] E = new Byte[count];
        //    Byte[] F = new Byte[count];
        //    int ec = 0;
        //    int oc = 0;
        //    for(int i=0; i < al.Count; i++)
        //    {
        //        if ( (i % 2) == 0 )
        //            E[ec++] = (byte)al[i];
        //        else
        //            F[oc++] = (byte)al[i];
        //    }
        //    SHA1 sha = SHA1.Create();
        //    Byte[] G = sha.ComputeHash(E);
        //    Byte[] H = sha.ComputeHash(F);

        //    // Interleave the two hashes back together to form the output, i.e.
        //    // result = G[0] | H[0] | G[1] | H[1] | ... | G[19] | H[19]
        //    // The result will be 40 bytes (320 bits) long.
        //    Byte[] key = new Byte[40];
        //    int step = 0;
        //    for(int i=0; i < G.Length; i++)
        //    {
        //        key[step] = G[i];
        //        key[step+1] = H[i];
        //        step+=2;
        //    }
        //    return key;
        //}
    }
}
