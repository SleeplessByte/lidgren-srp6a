using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network;
using Lidgren.Network.Authentication;

namespace Lidgren.Network.Lobby
{
    public static class NetLobby
    {
        /// <summary>
        /// Keysize of SRP
        /// </summary>
        public static Int32 KeySize = 1024;

        /// <summary>
        /// The LogonManager handler
        /// </summary>
        public static ILogonManager LogonManager;

        /// <summary>
        /// Delegate that runs when a handshake is finished
        /// </summary>
        /// <param name="reason"></param>
        public delegate void HandshakeFinishedEvent(String reason);

        /// <summary>
        /// On handshake denied (username/password failure)
        /// </summary>
        public static event HandshakeFinishedEvent OnDenied;
        
        /// <summary>
        /// On handshake succeeded
        /// </summary>
        public static event HandshakeFinishedEvent OnSucces;
        
        /// <summary>
        /// On handshake expired (timeout/old session)
        /// </summary>
        public static event HandshakeFinishedEvent OnExpired;
        
        /// <summary>
        /// On handshake error
        /// </summary>
        public static event HandshakeFinishedEvent OnError;

        /// <summary>
        /// Authenticates the connection
        /// </summary>
        /// <param name="connection">Connection to authenticate</param>
        /// <param name="username">Username</param>
        /// <param name="password">Password</param>
        /// <param name="data">Additional data to send</param>
        public static void Authenticate(NetConnection connection, String username, String password, Byte[] data = null)
        {
            var handshake = new Handshake(true, KeySize);
            var request = handshake.GenerateSRPRequest(username, password, data ?? new Byte[0]);

            var result = Create(connection, Handshake.Contents.Username, request.ByteSize);
            handshake.WriteSRPRequest(result);

            connection.SendMessage(result, NetDeliveryMethod.ReliableUnordered, 0);
            connection.Tag = handshake;

            Console.WriteLine("Autenticating with {0}:{1}", username, password);
        }

        /// <summary>
        /// Receives authentication
        /// </summary>
        /// <param name="message">Message with authentication</param>
        internal static void ReceiveAuthenticate(NetIncomingMessage message)
        {
            try
            {
                var handshake = new Handshake(false, KeySize, LogonManager);
                message.SenderConnection.Tag = handshake;
                var response = Handshake.HandshakeFromActive(message);
                var result = Create(message.SenderConnection, Handshake.Contents.Password, response.ByteSize);
                handshake.WriteSRPResponse(result);

                message.SenderConnection.SendMessage(result, NetDeliveryMethod.ReliableUnordered, 0);
                
                Console.WriteLine("Received with {0}", handshake.Username ?? handshake.UserData);
            }
            catch (Lidgren.Network.Authentication.NetSRP.HandShakeException ex)
            {
                ExceptionHandle(message, ex.Message);
                return;
            }

            
        }

        /// <summary>
        /// Receives authentication response
        /// </summary>
        /// <param name="message"></param>
        internal static void ReceiveResponse(NetIncomingMessage message)
        {
            try
            {
                var verification = Handshake.HandshakeFromPassive(message);
            }
            catch (Lidgren.Network.Authentication.NetSRP.HandShakeException ex)
            {
                ExceptionHandle(message, ex.Message);
                return;
            }

            var result = Create(message.SenderConnection, Handshake.Contents.Verification, 21);
            (message.SenderConnection.Tag as Handshake).WriteSRPVerification(result);

            message.SenderConnection.SendMessage(result, NetDeliveryMethod.ReliableUnordered, 0);
        }

        /// <summary>
        /// Receives active party verification
        /// </summary>
        /// <param name="message"></param>
        internal static void ReceiveActiveVerification(NetIncomingMessage message)
        {
            try
            {
                var verification = Handshake.FinishHandshakeFromActive(message);
            }
            catch (Lidgren.Network.Authentication.NetSRP.HandShakeException ex)
            {
                ExceptionHandle(message, ex.Message);
                return;
            }

            var result = Create(message.SenderConnection, Handshake.Contents.Verification, 21);
            (message.SenderConnection.Tag as Handshake).WriteSRPVerification(result);

            message.SenderConnection.SendMessage(result, NetDeliveryMethod.ReliableUnordered, 0);

            // Finished!
            (message.SenderConnection.Tag as Handshake).MarkHandshakeAsSucceeded();

            if (OnSucces != null)
                OnSucces.Invoke("Authentication completed!");
        }

        /// <summary>
        /// Recieves passive verification
        /// </summary>
        /// <param name="message"></param>
        internal static void ReceivePassiveVerification(NetIncomingMessage message)
        {
            try
            {
                var result = Handshake.FinishHandshakeFromPassive(message);
                // Finished!
            }
            catch (Lidgren.Network.Authentication.NetSRP.HandShakeException ex)
            {
                ExceptionHandle(message, ex.Message);
                return;
            }

            (message.SenderConnection.Tag as Handshake).MarkHandshakeAsSucceeded();

            if (OnSucces != null)
                OnSucces.Invoke("Authentication completed!");
        }

        /// <summary>
        /// Receives expired
        /// </summary>
        internal static void ReceiveFromExpired(NetIncomingMessage message)
        {
            var result = Create(message.SenderConnection, Handshake.Contents.Expired);
            message.SenderConnection.SendMessage(result, NetDeliveryMethod.ReliableUnordered, 0);
        }

        /// <summary>
        /// Handles exceptions
        /// </summary>
        /// <param name="message"></param>
        internal static void ExceptionHandle(NetIncomingMessage message, String reason)
        {
            Handshake.Contents contents;
            switch ((message.SenderConnection.Tag as Handshake).HandshakeState)
            {
                case Handshake.State.Failed:
                    contents = Handshake.Contents.Error;
                    if (OnError != null) OnError.Invoke(reason);
                    break;
                case Handshake.State.Expired:
                    contents = Handshake.Contents.Expired;
                    if (OnExpired != null) OnExpired.Invoke(reason);
                    break;
                case Handshake.State.Denied:
                    contents = Handshake.Contents.Denied;
                    if (OnDenied!= null) OnDenied.Invoke(reason);
                    break;

                default:
                    contents = Handshake.Contents.Error;
                    if (OnError != null) OnError.Invoke(reason);
                    break;
            }
            var result = Create(message.SenderConnection, contents);
            result.Write(reason);
            message.SenderConnection.SendMessage(result, NetDeliveryMethod.ReliableUnordered, 0);
        }

        /// <summary>
        /// Creates a new message
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="reason"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        private static NetOutgoingMessage Create(NetConnection connection, Handshake.Contents reason, Int32 size = 4)
        {
            var message = connection.Peer.CreateMessage(size);
            message.Write((Byte)reason);
            return message;
        }

        /// <summary>
        /// Handles incoming messages
        /// </summary>
        /// <param name="message"></param>
        public static Handshake.Contents IncomingMessage(NetIncomingMessage message)
        {
            switch (message.MessageType)
            {
                case NetIncomingMessageType.Data:
                    var reasonByte = message.ReadByte();

                    var reason = (Handshake.Contents)reasonByte;

                    Console.WriteLine("Got handshake {0}", reason);

                    var handshake = message.SenderConnection.Tag as Handshake;
                    switch (reason)
                    {
                        case Handshake.Contents.Succes:
                            if (OnSucces != null) OnSucces.Invoke("Authentication complete!");
                            return reason;
                        case Handshake.Contents.Error:
                            if (OnError != null) OnError.Invoke(message.ReadString());
                            return reason;
                        case Handshake.Contents.Denied:
                            if (OnDenied != null) OnDenied.Invoke(message.ReadString());
                            return reason;
                    }
                    if (handshake == null)  // Server
                    {
                        switch (reason)
                        {
                            case Handshake.Contents.Username:
                                ReceiveAuthenticate(message);
                                break;
                            default:
                                // Can't happen!
                                throw new Lidgren.Network.Authentication.NetSRP.HandShakeException("Handshake not initialized when receiving " + reason.ToString() + " from client");
                        }
                        return reason;
                    }
                    switch (handshake.HandshakeState)
                    {
                        case Handshake.State.Expired:
                        case Handshake.State.Denied:
                        case Handshake.State.NotInitialized: // Server
                            switch (reason)
                            {
                                case Handshake.Contents.Username:
                                    ReceiveAuthenticate(message);
                                    break;
                                default:
                                    // Can't happen!
                                    throw new Lidgren.Network.Authentication.NetSRP.HandShakeException("Handshake not initialized when receiving " + reason.ToString() + " from client");
                            }
                            break;
                        case Handshake.State.Succeeded:
                            return Handshake.Contents.Succes;

                        case Handshake.State.Requesting: // Client
                            switch (reason)
                            {
                                case Handshake.Contents.Password:
                                    ReceiveResponse(message);
                                    break;
                                case Handshake.Contents.Expired:
                                    Authenticate(message.SenderConnection, handshake.Username, handshake.UserData);
                                    break;
                                default:
                                    // Can't happen!
                                    throw new Lidgren.Network.Authentication.NetSRP.HandShakeException("Expected response but received: " + reason.ToString() + " from server");
                            }
                            break;
                        case Handshake.State.Responding: // Server
                            switch (reason)
                            {
                                case Handshake.Contents.Verification:
                                    ReceiveActiveVerification(message);
                                    break;
                                case Handshake.Contents.Expired:
                                    ReceiveFromExpired(message);
                                    break;
                                default:
                                    // Can't happen!
                                    throw new Lidgren.Network.Authentication.NetSRP.HandShakeException("Expected verification but received: " + reason.ToString() + " from client ");
                            }
                            break;
                        case Handshake.State.Verificating: // Client
                            switch (reason)
                            {
                                case Handshake.Contents.Expired:
                                    Authenticate(message.SenderConnection, handshake.Username, handshake.UserData);
                                    break;
                                case Handshake.Contents.Verification:
                                    ReceivePassiveVerification(message);
                                    break;
                                default:
                                    // Can't happen!
                                    throw new Lidgren.Network.Authentication.NetSRP.HandShakeException("Expected completion but received: " + reason.ToString() + " from server ");
                            }
                            break;
                        default:
                            throw new Lidgren.Network.Authentication.NetSRP.HandShakeException("Expected nothing but received: " + reason.ToString());
                    }
                    if (handshake.HandshakeState == Handshake.State.Succeeded)
                        return Handshake.Contents.Succes;

                    return reason;
            }
            return Handshake.Contents.None;
        }
    }
}
