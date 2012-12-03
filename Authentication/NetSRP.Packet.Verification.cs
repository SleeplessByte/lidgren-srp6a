using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    internal static partial class NetSRP
    {
        /// <summary>
        /// This is the Secure Remote Password Protocol Verification object. Claire and Bob need to validate
        /// all their computed and received information. So, they use all their information on both ends
        /// to validate all the information on the opposed end.
        /// </summary>
        internal class Verification : Packet
        {
            public Byte[] M;
            public Byte[] M2
            {
                get { return M; }
                set { M = value; }
            }

            /// <summary>
            /// Creates a new SRPVerification
            /// </summary>
            public Verification()
            {

            }

            /// <summary>
            /// Creates a new SRPVerification
            /// </summary>
            /// <param name="M">Verification Value (M or M2)</param>
            public Verification(Byte[] M)
            {
                this.M = M;
            }

            /// <summary>
            /// Puts data in message
            /// </summary>
            /// <param name="message"></param>
            protected override void Puts(NetOutgoingMessage message)
            {
                message.Write(this.M.Length);
                message.Write(this.M);
            }

            /// <summary>
            /// Gets data from message
            /// </summary>
            /// <param name="message"></param>
            protected override void Gets(NetIncomingMessage message)
            {
                this.M = message.ReadBytes(message.ReadInt32());
            }
        }
    }
}
