using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    public partial class Handshake
    {
        /// <summary>
        /// Processes a handshake that was not initated locally
        /// </summary>
        /// <param name="msg">Incomming msg with handshake</param>
        internal static NetSRP.Response HandshakeFromActive(NetIncomingMessage msg)
        {
            // Read request
            NetSRP.Request request = new NetSRP.Request();
            request.ExtractPacketData(msg);

            // Create response
            return (msg.SenderConnection.Tag as Handshake).ResponseFromRequest(request);
        }

        /// <summary>
        /// Create a response on received request.
        /// </summary>
        /// <param name="request">Receieved Request</param>
        /// <returns></returns>
        private NetSRP.Response ResponseFromRequest(NetSRP.Request request)
        {
            if (Handshake._defaultLogonManager == null)
                throw new NetSRP.HandShakeException("No HandShake.Passive functions are available until LogonManager is provided.");

            if (this.HandshakeState != Handshake.State.NotInitialized && (Handshake.State.AllowResponse & this.HandshakeState) != this.HandshakeState)
                return _response;

            // Set State and start timer
            this.HandshakeState = Handshake.State.Responding;
            _cache.ExpirationTime = DateTime.Now.AddSeconds(Handshake.ExpirationInSeconds);

            if (request.A.Mod(N).IntValue == 0)
            {
                this.HandshakeState = Handshake.State.Failed;
                throw new NetSRP.HandShakeException("Request contains invalid data", new ArgumentException("A mod N is zero."));
            }

            Byte[] salt;
            NetBigInteger v;

            // Get verifier
            try
            {
                v = Lookup(request, out salt);
            }
            catch (Exception exception)
            {
                this.HandshakeState = Handshake.State.Failed;
                throw new NetSRP.HandShakeException("LogonManager failed lookup.", exception);
            }

            if (v == null)
            {
                this.HandshakeState = Handshake.State.Denied;
                throw new NetSRP.HandShakeException("Wrong username or password."); // Clearly its username.
            }

            // Cache request
            _request = request;
            _cache.UserData = _request.Username;

            // Get public ket B from random private b
            _cache.b = NetSRP.Getb();
            _cache.B = NetSRP.CalcB(N, g, _cache.b, v);

            // Create the response message
            _response = new NetSRP.Response(salt, _cache.B);

            // First create the key
            KeyFromRequest(request.A, v);

            return _response;
        }

        /// <summary>
        /// 
        /// </summary>
        internal Int32 ResponseByteCount
        {
            get
            {
                return _response != null ? _response.ByteSize : 0;
            }
        }
        

        /// <summary>
        /// Writes the SRP Response to an OtugoingMessage
        /// </summary>
        /// <param name="om"></param>
        /// <returns></returns>
        internal NetOutgoingMessage WriteSRPResponse(NetOutgoingMessage om)
        {
            NetSRP.Response.GenerateMessage(om, _response);
            // this.HandShakeState = HandShake.State.Responded;
            return om;
        }

        /// <summary>
        /// Generates key from request
        /// </summary>
        /// <param name="A">Generated A from request</param>
        /// <param name="v">Verifier v</param>
        private void KeyFromRequest(NetBigInteger A, NetBigInteger v)
        {
            // Shared random scrambler
            Lidgren.Network.NetBigInteger u = NetSRP.Calcu(A, _cache.B);

            // Sessionkey
            _cache.S = NetSRP.CalcSServer(N, A, v, u, _cache.b);
            _cache.K = NetSRP.CalcK(_cache.S);
        }

        /// <summary>
        /// Finishes the handshake by processing the verification data received
        /// </summary>
        /// <param name="msg">Incomming message with verification data</param>
        internal static NetSRP.Verification FinishHandshakeFromActive(NetIncomingMessage msg)
        {
            // Get Verification
            NetSRP.Verification verification = new NetSRP.Verification();
            verification.ExtractPacketData(msg);

            // Try to verify data
            return (msg.SenderConnection.Tag as Handshake).VerificationOfActiveParty(verification);
        }

        /// <summary>
        /// Actually verifies received verification data (initiated remotely) + generates response
        /// </summary>
        /// <param name="verification"></param>
        private NetSRP.Verification VerificationOfActiveParty(NetSRP.Verification verification)
        {
            if ((Handshake.State.AllowVerificating & this.HandshakeState) != this.HandshakeState)
                return _verification; // double

            // Set State
            this.HandshakeState = Handshake.State.Verificating;
            
            // Hello I am the one that is being connected to. So let's generate 
            // the value M I should have in the SRPPackedData Object.
            Byte[] M = NetSRP.CalcM(N, g, _request.Username, _response.Salt, _request.A, _cache.B, _cache.K);
            
            // Compare
            if (!NetUtility.ArraysEqual(M, verification.M))
            {
                this.HandshakeState = Handshake.State.Denied | State.Failed;
                throw new NetSRP.HandShakeException("Invalid proof of Key. Username or password invalid.", new InvalidOperationException("Generated M does not match received M"));
            }

            // Ok, so their verification passed. Now let's proof that mine will to.
            _verification = new NetSRP.Verification(NetSRP.CalcM2(_request.A, verification.M, _cache.K));

            // Check expiration (maybe use timer?)
            if (_cache.ExpirationTime.CompareTo(DateTime.Now) < 0)
            {
                this.HandshakeState = Handshake.State.Expired;
                throw new NetSRP.HandShakeException("Hand was not shaken before it expired.");
            }

            return _verification;
        }
    }
}
