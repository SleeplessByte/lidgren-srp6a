using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network;
using Lidgren.Network.Authentication;
using System.Timers;

namespace SRPServer
{
    /// <summary>
    /// 
    /// </summary>
    internal class Connection : IDisposable
    {
        private Boolean _connected, _disposed;
        private INetEncryption _netEncryption;
        private Timer _keepAliveTimer;

        /// <summary>
        /// Lidgren NetConnection (Pipe)
        /// </summary>
        public NetConnection NetConnection { get; protected set; }

        /// <summary>
        /// Local Lidgrend NetPeer (Origin)
        /// </summary>
        public NetPeer NetManager { get; protected set; }

        /// <summary>
        /// Node id
        /// </summary>
        public String NodeId { get; set; }

        /// <summary>
        /// Node username
        /// </summary>
        public String Username { get; set; }

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
        /// Transfer flag
        /// </summary>
        public Boolean IsTransfering
        {
            get;
            set;
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
            // This keep alive timer is used to overcome BAD connections that drop ping/pong messages a lot.
            // It simply sends an empty message every five seconds. As long as some messages are retained
            // and received on the connection, all will be well
            _keepAliveTimer = new System.Timers.Timer(5000);
            _keepAliveTimer.Elapsed += new ElapsedEventHandler((Object state, ElapsedEventArgs args) => 
                this.SendMessage(this.NetManager.CreateMessage(0), NetDeliveryMethod.Unreliable));

            this.Username = (con.Tag as Handshake).Username;
            this.NetManager = manager;
            this.NetConnection = con;
            this.NetConnection.Tag = this;
            this.NodeId = nodeId;

            if (encryption != null)
            {
                _netEncryption = encryption;
            }
            else
            {
                // You could write code that makes it possible to transfer users between server
                // where you don't have any encryption key YET. The place to start that would
                // be here.
                this.IsTransfering = true;
                _netEncryption = new NetXtea(new Byte[16]);
            }

            // Not connected until everything is done.
            System.Threading.Thread.MemoryBarrier();

            _connected = true;
            _keepAliveTimer.Start();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="manager">Local NetPeer</param>
        /// <param name="con">NetConnection</param>
        /// <param name="key">Node Id</param>
        public Connection(NetPeer manager, NetConnection con, Byte[] key)
            : this(manager, con, key != null ? new NetXtea(key) : null, String.Empty)
        {

        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="con"></param>
        /// <param name="encryption"></param>
        public Connection(NetPeer manager, NetConnection con, INetEncryption encryption)
            : this(manager, con, encryption, String.Empty)
        {

        }

        /// <summary>
        /// Transfer constructor
        /// </summary>
        /// <param name="manager"></param>
        /// <param name="con"></param>
        public Connection(NetPeer manager, NetConnection con, String id)
            : this(manager, con, null, id) { }

        /// <summary>
        /// This handles an incoming message 
        /// </summary>
        /// <param name="msg">The received message</param>
        public void IncomingMessage(NetIncomingMessage msg)
        {
            if (!this.IsConnected)
                return;

            // Is this is a heartbeat message? (keep alive)
            if (msg.LengthBits == 0)
                return;

            // Decrypt the message
            msg.Decrypt(_netEncryption);
            if (msg.LengthBits == 0)
                return;

            // Here you can process your message like:
            Console.WriteLine("Received message: {0}", msg.ReadString());
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
            if(this.IsDisposed)
                return;

            _keepAliveTimer.Stop();
            _disposed = true;
            _keepAliveTimer.Dispose();
        }

        /// <summary>
        /// Sets the encryption for this connection (see the comments about transfering clients)
        /// </summary>
        /// <param name="key"></param>
        internal void SetEncryption(INetEncryption enc)
        {
            _netEncryption = enc;
        }
    }
}
