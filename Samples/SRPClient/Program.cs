using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network.Lobby;

namespace SRPClient
{
    class Program
    {
        static NetworkManager _manager;

        static void Main(string[] args)
        {
            _manager = new NetworkManager();
            _manager.OnAuthenticated += new NetworkManager.AuthenticationSucces(_manager_OnAuthenticated);
            _manager.OnAuthenticationStep += new NetworkManager.AuthenticationProgress(_manager_OnAuthenticationStep);
            _manager.OnAuthenticationFailed += new NetworkManager.AuthenticationFailure(_manager_OnAuthenticationFailed);
            _manager.OnAuthenticationTimeout += new NetworkManager.AuthenticationFailure(_manager_OnAuthenticationTimeout);
            _manager.OnAuthenticationDenied += new NetworkManager.AuthenticationFailure(_manager_OnAuthenticationDenied);
            _manager.Initialize();

            NetLobby.OnError += new NetLobby.HandshakeFinishedEvent(NetLobby_OnError);

            QueryDetails();

            while (_manager.IsRunning)
            {
                System.Threading.Thread.Sleep(1);
                System.Threading.Thread.MemoryBarrier();
            }

            Console.ReadKey();
        }

        /// <summary>
        /// Error occured
        /// </summary>
        /// <param name="reason"></param>
        static void NetLobby_OnError(string reason)
        {
            Console.WriteLine(">> Error: {0} <<", reason);
            QueryDetails();
        }

        /// <summary>
        /// Authentication denied
        /// </summary>
        /// <param name="reason"></param>
        static void _manager_OnAuthenticationDenied(string reason)
        {
            Console.WriteLine(">> Denied: {0} <<", reason);
            QueryDetails();
        }

        /// <summary>
        /// Authentication timeout
        /// </summary>
        /// <param name="reason"></param>
        static void _manager_OnAuthenticationTimeout(string reason)
        {
            Console.WriteLine(">> Timeout: {0} <<", reason);
            QueryDetails();
        }

        /// <summary>
        /// Authentication failed
        /// </summary>
        /// <param name="reason"></param>
        static void _manager_OnAuthenticationFailed(string reason)
        {
            Console.WriteLine(">> Failed: {0}", reason);
        }

        /// <summary>
        /// On Authentication progress
        /// </summary>
        /// <param name="step"></param>
        static void _manager_OnAuthenticationStep(AuthenticationStatus step)
        {
            Console.WriteLine("---- authentication step: {0} ----", step);
            if (step == AuthenticationStatus.NoServerFound)
            {
                _manager.Connect(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 15812));

                Console.WriteLine(">> Trying loopback:15812 <<");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="connection"></param>
        static void _manager_OnAuthenticated(Connection connection)
        {
            Console.WriteLine(">> Authenticated <<");
            Console.WriteLine("Hello! Say something");
            var sat = Console.ReadLine().Replace("\n", "").Replace("\r", "");
            var msg = connection.NetManager.CreateMessage();
            msg.Write(sat);

            connection.SendMessage(msg, Lidgren.Network.NetDeliveryMethod.ReliableOrdered);
            Console.WriteLine("Goodbye!");
            _manager.IsRunning = false;
        }

        /// <summary>
        /// Query for details
        /// </summary>
        static void QueryDetails()
        {
            _manager.CancelConnect();
            Console.Write("Username: ");
            var username = Console.ReadLine().Replace("\n", "").Replace("\r", "");
            Console.Write("Password: ");
            var password = String.Empty;
            var key = Console.ReadKey(true);
            while (key.Key != ConsoleKey.Enter)
            {
                password += key.KeyChar;
                key = Console.ReadKey(true);
            }
            Console.WriteLine();
            _manager.AsyncConnect(username, password);
        }
    }
}