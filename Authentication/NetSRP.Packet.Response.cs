using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    internal static partial class NetSRP
    {
        /// <summary>
        /// This is the Secure Remote Password Protocol Response object. Remember Claire?
        /// She has send a request to Bob, the one she want to connect to. When Bob receives
        /// Claire's username and public Key, he will send Claire her personal Salt and a 
        /// random runtime-generated public key.
        /// </summary>
        internal class Response : Packet
        {
            private Int32 _cachedSize;

            /// <summary>
            /// Salt
            /// </summary>
            public Byte[] Salt;

            /// <summary>
            /// Public key B
            /// </summary>
            public NetBigInteger B;

            /// <summary>
            /// Creates a new SRPResponse
            /// </summary>
            public Response()
            {
            }

            /// <summary>
            /// Creates a new SRPResponse
            /// </summary>
            /// <param name="salt">Salt</param>
            /// <param name="B">Public value</param>
            public Response(Byte[] salt, NetBigInteger B)
            {
                this.Salt = salt;
                this.B = B;
            }

            /// <summary>
            /// 
            /// </summary>
            public Int32 ByteSize
            {
                get
                {
                    if (!this.IsReadOnly)
                    {
                        _cachedSize = B.ToByteArray().Length + 4 + Salt.Length + 4;
                    }

                    return _cachedSize;
                }
            }

            /// <summary>
            /// Puts data into message
            /// </summary>
            /// <param name="message">desination</param>
            protected override void Puts(NetOutgoingMessage message)
            {
                Byte[] bytes = this.B.ToByteArray();
                message.Write(bytes.Length);
                message.Write(bytes);
                message.Write(this.Salt.Length);
                message.Write(this.Salt);
            }

            /// <summary>
            /// Gets data from message
            /// </summary>
            /// <param name="message">source</param>
            protected override void Gets(NetIncomingMessage message)
            {
                this.B = new NetBigInteger(message.ReadBytes(message.ReadInt32()));
                this.Salt = message.ReadBytes(message.ReadInt32());
            }
        }
    }
}
