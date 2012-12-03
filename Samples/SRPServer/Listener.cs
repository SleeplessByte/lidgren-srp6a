using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Lidgren.Network;
using Lidgren.Network.Lobby;
using Lidgren.Network.Authentication;

namespace SRPServer
{
    /// <summary>
    /// interfaces client <-> gameserver connections
    /// </summary>
    internal class Listener
    {
        /// <summary>
        /// Listener running on port
        /// </summary>
        public static Int32 Port { get; private set; }

        /// <summary>
        /// Handles the running switch
        /// </summary>
        public Boolean IsRunning { get; set; }
        
        /// <summary>
        /// Gets the net server
        /// </summary>
        public NetServer Server { get { return _server; } }

        /// <summary>
        /// Delegate used when a connection is established or broken
        /// </summary>
        /// <param name="nodeId"></param>
        /// <param name="username"></param>
        public delegate void ConnectionDelegate(String nodeId, String username);

        /// <summary>
        /// List of functions to call on connection
        /// </summary>
        public event ConnectionDelegate OnConnected = delegate { };

        /// <summary>
        /// List of functions to call on disconnect
        /// </summary>
        public event ConnectionDelegate OnDisconnected = delegate { };

        protected Thread _serverThread;
        protected NetServer _server;

        /// <summary>
        /// Client Listener
        /// </summary>
        public Listener()
        {
            // Configuration
            NetPeerConfiguration config = new NetPeerConfiguration("Lidgren.Authentication.Sample");
            config.EnableMessageType(NetIncomingMessageType.ConnectionApproval);
            config.Port = 15812;
            config.ConnectionTimeout = 60 * 15;
            config.UseMessageRecycling = true;

            _server = new NetServer(config);
            _server.Start();

            Listener.Port = config.Port;
        }

        /// <summary>
        /// Start running thread
        /// </summary>
        public void Start()
        {
            _serverThread = new Thread(new ThreadStart(ClientLoop));
            _serverThread.Name = "Client thread";

            this.IsRunning = true;

            _serverThread.Start();
        }

        /// <summary>
        /// Client message loop
        /// </summary>
        private void ClientLoop()
        {
            NetIncomingMessage msg;
            
            while (this.IsRunning)
            {
                _server.MessageReceivedEvent.WaitOne(1000);
                msg = _server.ReadMessage();

                // If this second no messages accepted, releave CPU
                if (msg == null)
                    continue;

                try
                {
                    switch (msg.MessageType)
                    {
                        // MESSAGETYPE: DATA
                        // The main message type in networking is the data type. When the connection is not linked, the
                        // data is the verification data of the handshake and will be processed accordingly. If not, 
                        // the message is passed onto the Connection and processed by their respective protocol.
                        case NetIncomingMessageType.Data:

                            var connection = msg.SenderConnection.Tag as Connection;
                            if (connection != null)
                            {
                                // Client was authenticated so just process the message
                                connection.IncomingMessage(msg);
                            }
                            else
                            {
                                // Client is not yet authenticate so handle that. In my case we directly expect
                                // authentication, but you can write your own handling code. The following code
                                // handles just that.
                                var handshake = NetLobby.IncomingMessage(msg);

                                switch (handshake)
                                {
                                    case Handshake.Contents.Succes:
                                        Connection new_connection = new Connection(_server, msg.SenderConnection, (msg.SenderConnection.Tag as Handshake).CreateEncryption());
                                        OnConnected.Invoke(new_connection.NodeId, new_connection.Username);
                                        break;

                                    case Handshake.Contents.Error:
                                    case Handshake.Contents.Denied:
                                        msg.SenderConnection.Disconnect("Error occured during handshake.");
                                        break;

                                    case Handshake.Contents.Expired:
                                        msg.SenderConnection.Disconnect("Handshake expired.");
                                        break;
                                }
                            }

                            break;

                        // MESSAGETYPE: CONNECTION APPROVAL
                        // The ConnectionApproval message type is seen when a node yields the peer#connect function. When
                        // the RemoteEndpoint specified is reached, a loose connection is made. It's up to the other end,
                        // the one that is connected too, to deny or approve the connection. 
                        case NetIncomingMessageType.ConnectionApproval:

                            // Here you can add approval code to the public section of the server
                           
                            msg.SenderConnection.Approve();
                        
                            break;

                        // MESSAGETYPE: STATUS CHANGED
                        // Internal type that is triggered when a connection is initiated, responded too, connecting,
                        // disconnecting, connected or disconnected. Upon a connection, we might have received some
                        // RemoteHailData. This is part of the SRPP protocol and is proccesed accordingly. When
                        // disconnecting, the Connection is disposed, internal connection is disconnected and all is
                        // logged. 
                        case NetIncomingMessageType.StatusChanged:

                            NetConnectionStatus statusByte = (NetConnectionStatus)msg.ReadByte();
                           
                            switch (statusByte)
                            {
                                case NetConnectionStatus.Disconnecting:
                                    break;

                                case NetConnectionStatus.Disconnected:
                                    // If already connection established, destroy resources
                                    var disconnected_connection = msg.SenderConnection.Tag as Connection;
                                    if (disconnected_connection != null)
                                    {
                                        OnDisconnected.Invoke(disconnected_connection.NodeId, disconnected_connection.Username);

                                        if (!disconnected_connection.IsDisposed)
                                            disconnected_connection.Dispose();
                                    }

                                    String finalReason = Encoding.UTF8.GetString(msg.ReadBytes((Int32)msg.ReadVariableUInt32()));
                                    // Do something with the message if you want like logging: Received a reason for disconnecting...
                                    break;

                                case NetConnectionStatus.Connected:
                                    break;

                                default:
                                    String statusChange = Encoding.UTF8.GetString(msg.ReadBytes((Int32)msg.ReadVariableUInt32()));
                                    // You can log/debug status messages here
                                    break;
                            }

                            break;

                            #if DEBUG
                            case NetIncomingMessageType.DebugMessage:
                                String debugMessage = Encoding.UTF8.GetString(msg.ReadBytes((Int32)msg.ReadVariableUInt32()));
                                // log
                                break;
                            #endif

                            case NetIncomingMessageType.WarningMessage:
                                String warningMessage = Encoding.UTF8.GetString(msg.ReadBytes((Int32)msg.ReadVariableUInt32()));
                                // log;
                                break;

                            case NetIncomingMessageType.ErrorMessage:
                                String errorMessage = Encoding.UTF8.GetString(msg.ReadBytes((Int32)msg.ReadVariableUInt32()));
                                // log
                                break;

                            default:
                                throw new NetException("MessageType: " + msg.MessageType + " is not supported.");
                        }

                    // Recycle please
                    _server.Recycle(msg);
                }
                catch(Exception e) 
                {
                    try
                    {
                        // Disconnect client on error
                        msg.SenderConnection.Disconnect("No tolerance: exception " + e.Message);
                    }
                    catch (Exception) { }
                }
            }
            
            // Early shutdown
            _server.Shutdown("Server shutting down");

            Console.WriteLine("Client Service is Stopping at " + NetTime.ToReadable(NetTime.Now));
            _server.Shutdown("Final shutdown");
        }
    }
}
