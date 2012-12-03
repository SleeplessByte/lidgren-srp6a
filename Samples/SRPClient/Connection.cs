using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network;

namespace SRPClient
{
    /// <summary>
    /// 
    /// </summary>
    internal class Connection : IDisposable
    {
        private Boolean _connected, _disposed;
        private INetEncryption _netEncryption;

        /// <summary>
        /// Lidgren NetConnection (Pipe)
        /// </summary>
        public NetConnection NetConnection { get; set; }

        /// <summary>
        /// Local Lidgrend NetPeer (Origin)
        /// </summary>
        public NetPeer NetManager { get; protected set; }

        /// <summary>
        /// Node id
        /// </summary>
        public String NodeId { get; set; }

        /// <summary>
        /// Connected flag
        /// </summary>
        public Boolean IsConnected
        {
            get { return _connected; }
        }

        /// <summary>
        /// Disposed flag
        /// </summary>
        public Boolean IsDisposed
        {
            get { return _disposed; }
        }

       
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="manager">Local NetPeer</param>
        /// <param name="con">NetConnection</param>
        /// <param name="key">Encryption key</param>
        /// <param name="nodeId">Node Id</param>
        public Connection(NetPeer manager, NetConnection con, INetEncryption encryption, String nodeId)
        {
            NetManager = manager;
            NetConnection = con;
            _connected = true;
            _netEncryption = encryption;
            NetConnection.Tag = this;
            NodeId = nodeId;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="manager">Local NetPeer</param>
        /// <param name="con">NetConnection</param>
        /// <param name="key">Node Id</param>
        public Connection(NetPeer manager, NetConnection con, Byte[] key)
            : this(manager, con, new NetXtea(key), "SomeNodeIdGenerationCode")
        {

        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="manager">Local NetPeer</param>
        /// <param name="con">NetConnection</param>
        /// <param name="key">Node Id</param>
        public Connection(NetPeer manager, NetConnection con, INetEncryption encryption)
            : this(manager, con, encryption, "SomeNodeIdGenerationCode")
        {

        }


        /// <summary>
        /// This handles an incoming message 
        /// </summary>
        /// <param name="msg">The received message</param>
        public void IncomingMessage(NetIncomingMessage msg)
        {
            if (!this.IsConnected)
                return;

            //Heartbeat
            if (msg.LengthBytes == 0)
                return;

            msg.Decrypt(_netEncryption);
            if (msg.LengthBits == 0)
                return;

            // Handle messages
            Console.WriteLine(msg.ReadString());
        }

        /// <summary>
        /// Sends a message
        /// </summary>
        /// <param name="msg">The message to send</param>
        /// <param name="method">The delivery method</param>
        /// <param name="sequenceChannel">The sequence channel</param>
        public void SendMessage(NetOutgoingMessage msg, NetDeliveryMethod method, Int32 sequenceChannel)
        {
            msg.Encrypt(_netEncryption);
            NetConnection.SendMessage(msg, method, sequenceChannel);
        }

        /// <summary>
        /// Sends a message
        /// </summary>
        /// <param name="msg">The message to send</param>
        /// <param name="method">The delivery method</param>
        public void SendMessage(NetOutgoingMessage msg, NetDeliveryMethod method)
        {
            SendMessage(msg, method, 0);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or 
        /// resetting unmanaged resources. Will deregister all protocols
        /// </summary>
        public void Dispose()
        {
            if (this.IsDisposed)
                return;

            _disposed = true;
        }

        /// <summary>
        /// Sets the key (when transfered servers)
        /// </summary>
        /// <param name="key"></param>
        internal void SetEncryptionKey(Byte[] key)
        {
            _netEncryption = new NetXtea(key);
        }

        /// <summary>
        /// Sets the encryption
        /// </summary>
        /// <param name="enc"></param>
        internal void SetEncryption(INetEncryption enc)
        {
            _netEncryption = enc;
        }
    }
}
