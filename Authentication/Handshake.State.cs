using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lidgren.Network.Authentication
{
    public partial class Handshake
    {
        [Flags]
        internal enum State : byte
        {
            NotInitialized = 0,
            Requesting = (1 << 0),
            Responding = (1 << 1),
            Verificating = (1 << 2),
            Succeeded = (1 << 3),
            Expired = (1 << 4),
            Failed = (1 << 5),
            Denied = (1 << 6),

            AllowRequest = Verificating | Expired | Failed | Denied | Succeeded,
            AllowResponse = Verificating | Expired | Failed | Denied | Succeeded,
            AllowVerificating = Responding | Requesting,
            AllowVerification = Verificating
        }
    }
}
