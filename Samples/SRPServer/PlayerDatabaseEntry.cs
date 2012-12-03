using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network.Authentication;
using Lidgren.Network;

namespace SRPServer
{
    [Serializable]
    internal class PlayerDatabaseEntry
    {
        /// <summary>
        /// Username for this user
        /// </summary>
        public String Username { get; set; }

        /// <summary>
        /// Verifier bytes
        /// </summary>
        public Byte[] Verifier { get; set; }

        /// <summary>
        /// Salt bytes
        /// </summary>
        public Byte[] Salt { get; set; }

        /// <summary>
        /// Current user is banned
        /// </summary>
        public Boolean IsBanned { get; set; }

        /// <summary>
        /// This functions generates a database entry for the given username and password. It
        /// is key that this function can only be called from a safe environment and that the 
        /// password is sent safely to this function. Think about SSL encryption or one time
        /// one way keys and so forth. Do your best! We actually generate these on the client
        /// so the password is NEVER sent over the network, and then sent it over an encrypted
        /// channel. 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="keysize"></param>
        /// <returns></returns>
        public static PlayerDatabaseEntry Generate(String username, String password, Int32 keysize)
        {
            Byte[] salt;

            // Calculates the verifier with a random salt
            // And we make sure the username is no longer case sensitive
            NetBigInteger verifier = Handshake.PasswordVerifier(username.ToLower().Trim(), password, keysize, out salt);

            // Returns the new entry
            return new PlayerDatabaseEntry() {
                Username = username, 
                Salt = salt, 
                Verifier = verifier.ToByteArray() 
            };
        }
    }
}
