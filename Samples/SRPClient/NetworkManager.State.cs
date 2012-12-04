using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network.Authentication;
using Lidgren.Network;
using Lidgren.Network.Lobby;
using System.Net;

namespace SRPClient
{
    internal partial class NetworkManager
    {
        private String _username, _password;
        private Handshake _handshake;
        private AuthenticationStatus _authenticationStep;
        private IPEndPoint _serverEP;

        /// <summary>
        /// Delegate used when authentication is completed
        /// </summary>
        /// <param name="connection"></param>
        public delegate void AuthenticationSucces(Connection connection);

        /// <summary>
        /// Delegate used when authentication failed
        /// </summary>
        /// <param name="reason"></param>
        public delegate void AuthenticationFailure(String reason);

        /// <summary>
        /// Delegate used when authentication status changes
        /// </summary>
        /// <param name="step"></param>
        public delegate void AuthenticationProgress(AuthenticationStatus step);

        /// <summary>
        /// List of functions called when authentication completed
        /// </summary>
        public event AuthenticationSucces OnAuthenticated = delegate { };

        /// <summary>
        /// List of functions called when authentication failed
        /// </summary>
        public event AuthenticationFailure OnAuthenticationFailed = delegate { };

        /// <summary>
        /// List of functions called when authentication denied (banned/password/username)
        /// </summary>
        public event AuthenticationFailure OnAuthenticationDenied = delegate { };

        /// <summary>
        /// List of functions called when authentication state changes
        /// </summary>
        public event AuthenticationProgress OnAuthenticationStep = delegate { };
        
        /// <summary>
        /// List of functions called when authentication timed out
        /// </summary>
        public event AuthenticationFailure OnAuthenticationTimeout = delegate { };


        /// <summary>
        /// 
        /// </summary>
        public void Loop()
        {
            try
            {
                // This is checked each cycle
                while (this.IsRunning)
                {
                    _client.MessageReceivedEvent.WaitOne(1000);
                    NetIncomingMessage msg = _client.ReadMessage();

                    // No message received, please relieve CPU
                    if (msg == null)
                        continue;

                    switch (msg.MessageType)
                    {
                        case NetIncomingMessageType.Data:
                            if (msg.SenderConnection.Tag is Connection)
                                ((Connection)msg.SenderConnection.Tag).IncomingMessage(msg);
                            else
                                NetLobby.IncomingMessage(msg);
                            break;

                        case NetIncomingMessageType.StatusChanged:
                            NetConnectionStatus statusByte = (NetConnectionStatus)msg.ReadByte();
                            switch (statusByte)
                            {
                                case NetConnectionStatus.Disconnecting:
                                    break;

                                // When disconnect is called and processed
                                case NetConnectionStatus.Disconnected:

                                    // If already connection established, destroy resources
                                    if (msg.SenderConnection.Tag is Connection &&
                                        !((Connection)msg.SenderConnection.Tag).IsDisposed)
                                        ((Connection)msg.SenderConnection.Tag).Dispose();

                                    // Received a reason for disconnecting? (e.a. Handshake Fail)
                                    String finalReason = Encoding.UTF8.GetString(msg.ReadBytes((Int32)msg.ReadVariableUInt32()));
                                    
                                    // Some exceptions that should be catched but even so
                                    if (finalReason.StartsWith("Handshake data validation failed"))
                                    {
                                        SetStep(AuthenticationStatus.NoServerConnection);
                                        OnAuthenticationFailed.Invoke("Could not connect");
                                    }
                                    else if (finalReason.StartsWith("Failed to establish"))
                                    {
                                        SetStep(AuthenticationStatus.NoServerConnection);
                                        OnAuthenticationTimeout.Invoke("Could not connect");
                                    }

                                    Disconnect("");
                                    break;

                                case NetConnectionStatus.Connected:
                                    SetStep(AuthenticationStatus.ServerConnection);

                                    var username = _username;
                                    var password = _password;

                                    // Connected so lets start authenticating
                                    Authenticate(_client.ServerConnection, _username, _password);
                                    break;
                            }
                            break;
                    }
                }

                Disconnect("");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        /// <summary>
        /// Setups lobby events
        /// </summary>
        public void SetupLobby()
        {
            NetLobby.OnDenied += new NetLobby.HandshakeFinishedEvent(NetLobby_OnDenied);
            NetLobby.OnError += new NetLobby.HandshakeFinishedEvent(NetLobby_OnError);
            NetLobby.OnExpired += new NetLobby.HandshakeFinishedEvent(NetLobby_OnExpired);
            NetLobby.OnSucces += new NetLobby.HandshakeFinishedEvent(NetLobby_OnSucces);
        }

        #region Events
        /// <summary>
        /// Runs when lobby succes
        /// </summary>
        /// <param name="reason"></param>
        void NetLobby_OnSucces(string reason)
        {
            _connection = new Connection(_client, _client.ServerConnection, (_client.ServerConnection.Tag as Handshake).CreateEncryption());
            
            try
            {
                OnAuthenticated.Invoke(_connection);
                SetStep(AuthenticationStatus.Authenticated);
            }
            catch (InvalidOperationException)
            {
                OnAuthenticationFailed.Invoke("Error occured while creation Connection");
                SetStep(AuthenticationStatus.HandshakeFailed);
            }
        }

        /// <summary>
        /// Runs when handshake expired
        /// </summary>
        /// <param name="reason"></param>
        void NetLobby_OnExpired(string reason)
        {
            SetStep(AuthenticationStatus.HandshakeExpired);

            // Simple timeout so lets try again
            var username = _username;
            var password = _password;
            Authenticate(_client.ServerConnection, _username, _password);
        }

        /// <summary>
        /// Runs when handshake error occrus
        /// </summary>
        /// <param name="reason"></param>
        void NetLobby_OnError(string reason)
        {
            OnAuthenticationFailed.Invoke(reason);
            Disconnect("Error during handshake: " + reason);
        }

        /// <summary>
        /// Runs when handshake is denied
        /// </summary>
        /// <param name="reason"></param>
        void NetLobby_OnDenied(string reason)
        {
            OnAuthenticationDenied.Invoke(reason);
            Disconnect("User denied " + reason);
        }
        #endregion

        /// <summary>
        /// Starts connecting with username and password
        /// </summary>
        /// <param name="username">username</param>
        /// <param name="password">password</param>
        public void AsyncConnect(String username, String password)
        {
            if (_authenticationStep == AuthenticationStatus.None || AuthenticationStatus.CanConnect.HasFlag(_authenticationStep))
            {
                // Save credentials
                _username = username.ToLower().Trim();
                _password = password;

                // Find server to connect to
                AsyncFindNearbyServer();
            }
        }

        /// <summary>
        /// Cancells any running connections
        /// </summary>
        internal void CancelConnect()
        {
            if (_client != null)
                _client.Disconnect("Cancelled connecting");

            SetStep(AuthenticationStatus.Cancelled);
        }

        /// <summary>
        /// Starts finding a nearby server asynchronously
        /// </summary>
        public void AsyncFindNearbyServer(Boolean newServer)
        {
            SetStep(AuthenticationStatus.FindServer);

            // Here you could provide the code to find a server and then
            _foundAServerCallbackMethod(this, EventArgs.Empty);
        }

        /// <summary>
        /// Async finds new server
        /// </summary>
        public void AsyncFindNearbyServer()
        {
            AsyncFindNearbyServer(false);
        }

        /// <summary>
        /// Event handler for completion of server retrieval
        /// </summary>
        /// <param name="sender">Source</param>
        /// <param name="e">Event arguments</param>
        private void _foundAServerCallbackMethod(object sender, EventArgs e)
        {
            SetStep(AuthenticationStatus.ServerFound);

            // Since we don't search for a server we set it manually
            IPAddress server = Lidgren.Network.NetUtility.Resolve("localhost");

            // Save the server and start the hand shake
            _serverEP = new IPEndPoint(server, ServerPort);
            Connect(_serverEP);
        }

        /// <summary>
        /// Connects to an endpoint
        /// </summary>
        /// <param name="endPoint"></param>
        public void Connect(IPEndPoint endPoint)
        {
            _client.Connect(endPoint);
        }

        /// <summary>
        /// Starts authenticating the user
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public void Authenticate(NetConnection connection, String username, String password)
        {
            // Hey we can't yet, connect first
            if (!IsConnected)
            {
                Connect(_serverEP);
                return;
            }

            SetStep(AuthenticationStatus.ServerConnection);

            NetLobby.Authenticate(connection, username, password);
            _handshake = connection.Tag as Handshake;

            SetStep(AuthenticationStatus.HandshakeData);
        }

        /// <summary>
        /// Sets authentication setp
        /// </summary>
        /// <param name="status"></param>
        private void SetStep(AuthenticationStatus status)
        {
            if (_authenticationStep == status)
                return;

            _authenticationStep = status;
            OnAuthenticationStep.Invoke(status);
        }

        /// <summary>
        /// Disconnects client and resets connecting status
        /// </summary>
        /// <param name="message">message to disconnect with</param>
        public void Disconnect(String message)
        {
            if (_client != null)
            {
                if (_client.ServerConnection != null && _client.ServerConnection.Status != NetConnectionStatus.Disconnected)
                    _client.Disconnect(message);
            }

            _serverEP = null;
            _handshake = null;
            _connection = null;
            SetStep(AuthenticationStatus.None);
        }
    }
}