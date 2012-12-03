using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    public partial class Handshake
    {
        /// <summary>
        /// Returns Verifier and Salt for request
        /// </summary>
        /// <param name="request">Request data</param>
        /// <param name="salt">salt output</param>
        /// <returns>verifier</returns>
        private NetBigInteger Lookup(NetSRP.Request request, out Byte[] salt)
        {
            return _logonManager.Lookup(request.Username, request.OtherData, out salt);
        }

        /// <summary>
        /// Generates Salt and Verifier for username and password
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="keysize"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static NetBigInteger PasswordVerifier(String username, String password, Int32 keysize, out Byte[] salt)
        {
            salt = NetSRP.GenerateSalt();
            NetBigInteger g, N = NetSRP.GetNandG(keysize, out g);
            return NetSRP.PasswordVerifier(username, password, salt, N, g);
        }
    }

    /// <summary>
    /// The LogonManager interface provides a tunnel to lookup all kinds of logons. Simply provide
    /// salt and verifier as out and return value to enable the manager to be used with NetSRP
    /// </summary>
    public partial interface ILogonManager
    {
        /// <summary>
        /// Lookup user + additional data and get corresponding salt and verifier, 
        /// simply return null if user does not exist
        /// </summary>
        /// <param name="username">username</param>
        /// <param name="data">other user data</param>
        /// <param name="salt">out salt</param>
        /// <returns>Verifier</returns>
        NetBigInteger Lookup(String username, Byte[] data, out Byte[] salt);
    }
}
