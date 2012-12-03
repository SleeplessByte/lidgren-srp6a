using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network.Authentication;
using Lidgren.Network;

namespace SRPServer
{
    internal class LogonManager : ILogonManager
    {
        private String _secret;
        private Int32 _keySize;

        /// <summary>
        /// Creates a new logon manager
        /// </summary>
        /// <param name="secret"></param>
        /// <param name="keySize"></param>
        public LogonManager(Int32 keySize, String secret = null)
        {
            _secret = secret;
            _keySize = keySize;
        }

        /// <summary>
        /// Looks up username in the database. Provide data for more finegrained searches. 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public NetBigInteger Lookup(String username, Byte[] data, out Byte[] salt)
        {
            // SERVER LOOKUP
            // You could connect servers with eachother using this same protocol. Let's say we defined
            // this by passing 31 to data[0]. Safer would be to use a code generator, such as google
            // authenticator. It's very easy to implement and a lot more secure. But for the sake of
            // sample, this code allows a server to authenticate with username, pre-set _secret.

            // You could ALSO use data to decide between different servers (alpha, beta, gamma) but keep
            // the logging in centralized. Use it however you like. 

            if (data != null && data.Length > 0 && data[0] == 31)
            {
                return Handshake.PasswordVerifier(username, _secret, _keySize, out salt);
            }

            // USER LOOKUP
            // Here you would lookup the player from the database. A sample database entry class is 
            // provided. Most safe would be to seperate verifier/salt data from player information
            // as you don't need the former after authentication. 
            salt = new Byte[0];

            // Get salt and v from the database. This means that the verifier was already generated, 
            // preferably on adding into the database. Make sure this step is secure.
            var player = PlayerDatabase.Find(username);
            if (player == null || String.IsNullOrEmpty(player.Username))
                return null;
            if (player.IsBanned)
                throw new Exception("That player (" + username + ") is banned.");

            // Set salt and obtained username
            salt = player.Salt;
            username = player.Username;
            return new NetBigInteger(1, player.Verifier);

        }
    }
}
