using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    public partial class Handshake
    {
        /// <summary>
        /// 
        /// </summary>
        [Flags]
        public enum Contents : byte
        {
            /// <summary>
            /// Invalid reason
            /// </summary>
            None = 0,

            /// <summary>
            /// Handshake completed. Message contains key as 32 bytes
            /// </summary>
            Succes = (1 << 0),

            /// <summary>
            /// Username/Request flag
            /// </summary>
            Username = (1 << 1),
            /// <summary>
            /// Password/Response flag
            /// </summary>
            Password = (1 << 2),
            /// <summary>
            /// Handshake denied. Alone or together with Username or Password flag. Message contains reason.
            /// </summary>
            Denied = (1 << 3),

            /// <summary>
            /// Handshake error. Message contains reason (exception message).
            /// </summary>
            Error = (1 << 4),
            /// <summary>
            /// Handshake expired.
            /// </summary>
            Expired = (1 << 5),

            /// <summary>
            /// Upgrade flag
            /// </summary>
            Upgrade = (1 << 6),
            /// <summary>
            /// Upgrade Request, internal use
            /// </summary>
            UpgradeRequest = Upgrade | (1 << 1),
            /// <summary>
            /// Upgrade Response, internal use
            /// </summary>
            UpgradeResponse = Upgrade | (1 << 2),
            /// <summary>
            /// Upgrade Verification, internal use
            /// </summary>
            UpgradeVerification = Upgrade | (1 << 7),

            /// <summary>
            /// Verification Message, internal use
            /// </summary>
            Verification = (1 << 7)
        }
    }
}
