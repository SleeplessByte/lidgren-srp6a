using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    internal static partial class NetSRP
    {
        /// <summary>
        /// This is the Secure Remote Password Protocol Request object. If Claire is someone that 
        /// tries to connect, then Claire's username and a random runtime-generated public key
        /// is packed into this packet.
        /// </summary>
        internal class Request : Packet
        {
            private Int32 _cachedSize;

            /// <summary>
            /// Username
            /// </summary>
            public String Username;

            /// <summary>
            /// Other Data
            /// </summary>
            public Byte[] OtherData = new Byte[0];

            /// <summary>
            /// Public key A
            /// </summary>
            public NetBigInteger A;

            /// <summary>
            /// Creates a new SRPRequest
            /// </summary>
            /// <param name="username">username</param>
            /// <param name="A">Public value</param>
            public Request(String username, NetBigInteger A)
            {
                this.Username = username;
                this.A = A;
            }

            /// <summary>
            /// Creates a new SRPRequest
            /// </summary>
            /// <param name="username">username</param>
            /// <param name="A">Public value</param>
            /// <param name="otherData">Other login data</param>
            public Request(String username, NetBigInteger A, Byte[] otherData)
            {
                this.Username = username;
                this.A = A;
                this.OtherData = otherData;
            }

            /// <summary>
            /// Creates a new SRPRequest
            /// </summary>
            public Request()
            {
            }

            /// <summary>
            /// Returns the number of bytes this instance will try to allocate when generated as message
            /// </summary>
            public Int32 ByteSize
            {
                get
                {
                    if (!this.IsReadOnly)
                    {
                        Int32 ubytes = Encoding.UTF8.GetByteCount(Username);
                        _cachedSize = ubytes + (ubytes > 127 ? 2 : 1) + 4 + OtherData.Length + 4 + A.ToByteArray().Length;
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
                message.Write(this.Username);
                message.Write(this.OtherData.Length);
                if (this.OtherData.Length > 0)
                    message.Write(this.OtherData);
                Byte[] bytes = this.A.ToByteArray();
                message.Write(bytes.Length);
                message.Write(bytes);
            }

            /// <summary>
            /// Gets data from message
            /// </summary>
            /// <param name="message">source</param>
            protected override void Gets(NetIncomingMessage message)
            {
                this.Username = message.ReadString();
                Int32 bytes = message.ReadInt32();
                this.OtherData = bytes > 0 ? message.ReadBytes(bytes) : new Byte[0];
                this.A = new NetBigInteger(message.ReadBytes(message.ReadInt32()));
            }

        }
    }
}
