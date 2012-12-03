using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Lidgren.Network.Lobby;
using System.Threading;

namespace SRPServer
{
    class Program
    {
        /// <summary>
        /// Server is Running
        /// </summary>
        public static Boolean IsRunning
        {
            set
            {
                if (value) StopRunningSemaphore.Reset();
                else StopRunningSemaphore.Set();
            }
        }

        /// <summary>
        /// Signals the thread if it can stop running
        /// </summary>
        private static ManualResetEvent StopRunningSemaphore { get; set; }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            // On the server a logon manager needs to be defined. Write a logonmanager class that handles logins
            NetLobby.LogonManager = new LogonManager(NetLobby.KeySize, "There is no secret.");
            StopRunningSemaphore = new ManualResetEvent(false);

            PlayerDatabase.Add(PlayerDatabaseEntry.Generate("test", "pass", NetLobby.KeySize));

            var listener = new Listener();
            listener.OnConnected += new Listener.ConnectionDelegate(listener_OnConnected);
            listener.OnDisconnected += new Listener.ConnectionDelegate(listener_OnDisconnected);

            listener.Start();
            Console.WriteLine("Server started.");

            // Runs this server until IsRunning is set to false
            StopRunningSemaphore.WaitOne();
            listener.IsRunning = false;
            Console.WriteLine("Server terminated.");
        }

        /// <summary>
        /// Function that runs when client disconnects
        /// </summary>
        /// <param name="nodeId"></param>
        /// <param name="username"></param>
        static void listener_OnDisconnected(string nodeId, string username)
        {
            Console.WriteLine("{0}:{1} disconnected", nodeId, username);
        }

        /// <summary>
        /// Function that runs when client connects
        /// </summary>
        /// <param name="nodeId"></param>
        /// <param name="username"></param>
        static void listener_OnConnected(string nodeId, string username)
        {
            Console.WriteLine("{0} connected with {1}", nodeId, username);
        }
    }
}
