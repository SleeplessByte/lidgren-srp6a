using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network;
using System.Security.Cryptography;

namespace Lidgren.Network.Authentication
{
    /// <summary>
    /// Handshake concentrates all SRPFunctions and SRPPacketData objects
    /// </summary>
    public partial class Handshake
    {
        internal static ILogonManager _defaultLogonManager;
        private static Double ExpirationInSeconds = 22;

        private Int32 _keySize;
        private NetBigInteger g, N;
        private NetBigInteger k;
        private ILogonManager _logonManager;

        private NetSRP.Request _request;
        private NetSRP.Response _response;
        private NetSRP.Verification _verification;
        private NetSRP.State _cache;

        /// <summary>
        /// Current HandShake State
        /// </summary>
        internal Handshake.State HandshakeState
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the received username 
        /// </summary>
        public String Username
        {
            get { return _request.Username; }
        }

        /// <summary>
        /// Gets the received userdata (remote username or local password)
        /// </summary>
        public String UserData
        {
            get { return _cache.UserData; }
        }

        /// <summary>
        /// Creates a new Handshake
        /// </summary>
        /// <param name="active">Is active party</param>
        /// <param name="keySize">keysize</param>
        /// <param name="logonManager">logonManager (only needed if passive)</param>
        internal Handshake(Boolean active, Int32 keySize, ILogonManager logonManager)
        {
            // Local Data setup
            _cache = new NetSRP.State();
            _keySize = keySize;
            _logonManager = logonManager ?? _defaultLogonManager;

            if (!active && _defaultLogonManager == null)
                _defaultLogonManager = logonManager;

            // We calculate N and G for this insance. I choose to do so, so you can
            // have different keysizes throughout your program and are not stuck with one
            N = NetSRP.GetNandG(_keySize, out g);
            k = NetSRP.Calck(N, g);

            // Set as NotInitialized
            this.HandshakeState = Handshake.State.NotInitialized;

            if (!active && _logonManager == null)
                throw new InvalidOperationException("Receiving handshakes need a logonManager");

            if (keySize == 0 || N == null || g == null || k == null)
                throw new InvalidOperationException("Handshake not intialized");

            // NOTE: this is caused by the length of the hailmessage - larger then 4096 goes over the MTU
            if (keySize < 1024 || keySize > 4096)
                throw new NetException("SRP6Keysize is not supported by Lidgren.Network",
                    new ArgumentOutOfRangeException("keySize"));
        }

        /// <summary>
        /// Creates a new handshake
        /// </summary>
        /// <param name="active"></param>
        /// <param name="keysize"></param>
        internal Handshake(Boolean active, Int32 keysize)
            : this(active, keysize, active ? null : _defaultLogonManager)
        {

        }

        /// <summary>
        /// Creates a completed handshake
        /// </summary>
        /// <param name="username"></param>
        /// <param name="key"></param>
        public Handshake(String username, Byte[] key)
        {
            _cache = new NetSRP.State();
            _cache.K = key;
            _request = new NetSRP.Request(username, null);

            this.HandshakeState = State.Succeeded;
        }

        /// <summary>
        /// Writes verification data to message
        /// </summary>
        /// <param name="om"></param>
        /// <returns></returns>
        internal NetOutgoingMessage WriteSRPVerification(NetOutgoingMessage om)
        {
            NetSRP.Verification.GenerateMessage(om, _verification);
            // this.HandShakeState = HandShake.State.Verificated;
            
            return om;
        }

        /// <summary>
        /// Sets handshake to done
        /// </summary>
        internal void MarkHandshakeAsSucceeded()
        {
            this.HandshakeState = Handshake.State.Succeeded;
        }

        /// <summary>
        /// Returns generated Session Bytes
        /// </summary>
        /// <returns></returns>
        internal Byte[] SessionBytes
        {
            get
            {
                return (_cache != null ? _cache.K ?? new Byte[32] : new Byte[32]);
            }
        }

        /// <summary>
        /// Create XTEA symmetrical encryption object from sessionValue
        /// </summary>
        public NetXtea CreateEncryption()
        {
            HashAlgorithm sha = SHA1.Create();
            Byte[] hash = sha.ComputeHash(SessionBytes);

            Byte[] key = new Byte[16];
            for (Int32 i = 0; i < 16; i++)
            {
                key[i] = hash[i];
                for (Int32 j = 1; j < hash.Length / 16; j++)
                    key[i] ^= hash[i + (j * 16)];
            }

            return new NetXtea(key);
        }

        /*  n 	A large prime number. All computations are performed modulo n.
            g 	A primitive root modulo n (often called a generator)
            s 	A random string used as the user's salt
            P 	The user's password
            x 	A private key derived from the password and salt
            v 	The host's password verifier
            u 	Random scrambling parameter, publicly revealed
            a,b 	Ephemeral private keys, generated randomly and not publicly revealed
            A, B 	Corresponding public keys
            H() 	One-way hash function
            m,n 	The two quantities (strings) m and n concatenated
            K 	Session key 
    
            x = H(s, P)    private key:         hashfunctie [salt (on server /w username), password (on client)]
            v = g^x        password verifier:   generator ^ private key 
            A = g^a        public key:          generator ^ emp private key (on client)
 		    
            B = v + g^b    public key:          verifier (on server /w username) + generator ^ emp private key (on server)
         
 	        S = (B - g^x)^(a + ux) 
            S = (A · v^u)^b
         
            K = H(S)
         
            M[1] = H(A, B, K)
            M[2] = H(A, M[1], K)
         */
    }
}
