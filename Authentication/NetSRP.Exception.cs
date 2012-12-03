using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    internal static partial class NetSRP
    {
        /// <summary>
        /// Exception thrown as part of the authentication
        /// </summary>
        internal class HandShakeException : Exception
        {
            /// <summary>
            /// Creates new Handshake Exception
            /// </summary>
            /// <param name="message"></param>
            public HandShakeException(String message)
                : base(message)
            {

            }

            /// <summary>
            /// Creates new Handshake Exception
            /// </summary>
            /// <param name="message"></param>
            /// <param name="innerException"></param>
            public HandShakeException(String message, Exception innerException)
                : base(message, innerException)
            {

            }
        }
    }
}
