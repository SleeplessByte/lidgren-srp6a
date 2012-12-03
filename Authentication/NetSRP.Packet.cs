using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network;

namespace Lidgren.Network.Authentication
{
    internal static partial class NetSRP
    {

        /// <summary>
        /// Base class for SRP Packets
        /// </summary>
        internal abstract class Packet
        {
            private Boolean _marked;
            private Boolean _readOnly;

            /// <summary>
            /// When a message is generated, it is marked in 
            /// the request object, so that you know request is going on
            /// </summary>
            public Boolean IsMessageGenerated
            {
                get { return _marked; }
            }

            /// <summary>
            /// When a message is generated from extracted data
            /// no message may be generated from this data
            /// </summary>
            public Boolean IsReadOnly
            {
                get { return _readOnly; }
            }

            /// <summary>
            /// Mark that a message was generated
            /// </summary>
            private void Mark()
            {
                _marked = true;
            }

            /// <summary>
            /// Generates a message
            /// </summary>
            /// <param name="result">result to generate to</param>
            /// <param name="data">data to generate from</param>
            /// <returns>Message containing data</returns>
            public static NetOutgoingMessage GenerateMessage(NetOutgoingMessage result, Packet data)
            {
                if (data.IsReadOnly)
                    throw new HandShakeException("Can not generate a message from a readonly packet");

                // TODO: check for expiration time
                result.WritePadBits();
                data.Puts(result);
                result.WritePadBits();
                data.Mark();

                return result;
            }

            /// <summary>
            /// Extracts the data from a message
            /// </summary>
            /// <param name="message">message packed with data</param>
            public void ExtractPacketData(NetIncomingMessage message)
            {
                try
                {
                    message.SkipPadBits();
                    Gets(message);
                    message.SkipPadBits();
                }
                catch (NetException)
                {
                    CorruptPackage();
                }
                catch (ArgumentOutOfRangeException)
                {
                    CorruptPackage();
                }
                catch (IndexOutOfRangeException)
                {
                    CorruptPackage();
                }

                _readOnly = true;
            }

            /// <summary>
            /// Packet corrupted
            /// </summary>
            /// <remarks>throws a HandshakeException</remarks>
            private void CorruptPackage()
            {
                throw new HandShakeException("Received data was corrupt, of type " + this.GetType().Name );
            }

            /// <summary>
            /// Puts packet data into message
            /// </summary>
            /// <param name="message"></param>
            protected abstract void Puts(NetOutgoingMessage message);

            /// <summary>
            /// Gets packet data from message
            /// </summary>
            /// <param name="message"></param>
            protected abstract void Gets(NetIncomingMessage message);
        }
    }
}
