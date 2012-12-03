using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    public partial class Handshake
    {

        /// <summary>
        /// Initiates the SRPP Request
        /// </summary>
        /// <param name="username">Username to login with</param>
        /// <param name="password">Password to login with</param>
        /// <param name="otherdata">Other data passed to LogonManager</param>
        /// <returns></returns>
        internal NetSRP.Request GenerateSRPRequest(String username, String password, Byte[] otherdata)
        {
            if ((this.HandshakeState != Handshake.State.NotInitialized) && (Handshake.State.AllowRequest & this.HandshakeState) != this.HandshakeState)
                return _request; // Already Created

            if (username == null || password == null)
                throw new NetSRP.HandShakeException("Need username and password to created SRP.Request");

            // Set state and timer
            this.HandshakeState = Handshake.State.Requesting;
            _cache.ExpirationTime = DateTime.Now.AddSeconds(Handshake.ExpirationInSeconds);

            // First get the public key A from random private a
            _cache.a = NetSRP.Geta();
            _cache.A = NetSRP.CalcA(N, g, _cache.a);

            // Save the password to use when the response comes in
            _cache.UserData = password;

            // Create a new request
            _request = new NetSRP.Request(username, _cache.A, otherdata);

            return _request;
        }

        /// <summary>
        /// 
        /// </summary>
        internal Int32 RequestByteCount
        {
            get {
                return _request != null ? _request.ByteSize : 0;
            }
        }

        /// <summary>
        /// Writes the SRP Request to an OtugoingMessage
        /// </summary>
        /// <param name="om"></param>
        /// <returns></returns>
        internal NetOutgoingMessage WriteSRPRequest(NetOutgoingMessage om)
        {
            NetSRP.Request.GenerateMessage(om, _request);
            // this.HandShakeState = HandShake.State.Requested;
            return om;
        }

        /// <summary>
        /// Processes a handshake response (initiated locally)
        /// </summary>
        /// <param name="msg">Incoming message with resonse data</param>
        internal static NetSRP.Verification HandshakeFromPassive(NetIncomingMessage msg)
        {
            // Get response
            NetSRP.Response response = new NetSRP.Response();
            response.ExtractPacketData(msg);

            // Create Verification data
            return (msg.SenderConnection.Tag as Handshake).KeyFromResponse(response);
        }

        /// <summary>
        /// Generates Session key from response
        /// </summary>
        /// <param name="response"></param>
        /// <response></response>
        private NetSRP.Verification KeyFromResponse(NetSRP.Response response)
        {
            if ((Handshake.State.AllowVerificating & this.HandshakeState) != this.HandshakeState)
                return _verification; // Double Request

            // When we get the response, get their public key B
            if (response.B.Mod(N).IntValue == 0)
            {
                this.HandshakeState = Handshake.State.Failed;
                throw new NetSRP.HandShakeException("Response contains invalid data", new ArgumentException("B mod N is zero."));
            }

            // Shared random scrambler
            NetBigInteger u = NetSRP.Calcu(_cache.A, response.B);
            if (u.IntValue == 0)
            {
                this.HandshakeState = Handshake.State.Failed;
                throw new NetSRP.HandShakeException("Response contains invalid data", new ArgumentException("u is zero."));
            }

            // Private key x
            NetBigInteger x = NetSRP.Calcx(response.Salt, _request.Username, _cache.UserData);

            // Cache Response;
            _response = response;

            // Session key
            _cache.S = NetSRP.CalcSClient(N, g, response.B, k, x, _cache.a, u);
            _cache.K = NetSRP.CalcK(_cache.S);


            // Create the verification
            _verification = new NetSRP.Verification(NetSRP.CalcM(N, g, _request.Username, response.Salt, _cache.A, response.B, _cache.K));

            // Set State
            this.HandshakeState = Handshake.State.Verificating;
            return _verification;
        }

        /// <summary>
        /// Finishes the handshake by processing the verification data received
        /// </summary>
        /// <param name="msg">Incomming message with verification data</param>
        internal static Boolean FinishHandshakeFromPassive(NetIncomingMessage msg)
        {
            // Get Verification
            NetSRP.Verification verification = new NetSRP.Verification();
            verification.ExtractPacketData(msg);

            // Try to verify data
            return (msg.SenderConnection.Tag as Handshake).VerificationOfPassiveParty(verification);
        }

        /// <summary>
        /// Actually verifies received verification data (initiated locally)
        /// </summary>
        /// <param name="verification"></param>
        private Boolean VerificationOfPassiveParty(NetSRP.Verification verification)
        {
            if ((Handshake.State.AllowVerification & this.HandshakeState) != this.HandshakeState)
                return false;

            // Hello I am the one that tries to connect. So let's generate the
            // value M2 I should have in the SRPPackedData Object.
            Byte[] M2 = NetSRP.CalcM2(_cache.A, _verification.M, _cache.K);

            // Compare
            if (!NetUtility.ArraysEqual(M2, verification.M2))
            {
                this.HandshakeState = Handshake.State.Failed;
                throw new NetSRP.HandShakeException("Username or password invalid.", new ArgumentException("Generated M2 does not match received M2"));
            }

            // Check expiration
            if (_cache.ExpirationTime.CompareTo(DateTime.Now) < 0)
            {
                this.HandshakeState = Handshake.State.Expired;
                throw new NetSRP.HandShakeException("Hand was not shaken before it expired.");
            }

            return true;
        }
    }
}
