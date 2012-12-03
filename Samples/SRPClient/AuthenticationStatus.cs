using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SRPClient
{
    /// <summary>
    /// 
    /// </summary>
    [Flags]
    public enum AuthenticationStatus
    {
        None = 0,

        FindServer = (1 << 0),
        ServerFound = (1 << 1),
        ServerConnection = (1 << 2),
        HandshakeData = (1 << 3),
        HandshakeVerification = (1 << 4),
        Authenticated = (1 << 5),

        HandshakeFailed = (1 << 6),
        HandshakeExpired = (1 << 7),
        HandshakeDenied = (1 << 8),

        NoServerFound = (1 << 9),
        NoServerConnection = (1 << 10),
        Cancelled = (1 << 11),

        CanConnect = NoServerFound | NoServerConnection | Cancelled | HandshakeFailed | HandshakeExpired | HandshakeDenied,

        IsAuthenticating = HandshakeData | HandshakeVerification,
        IsConnecting = FindServer | ServerFound,
        IsConnected = ServerConnection,
    }
}