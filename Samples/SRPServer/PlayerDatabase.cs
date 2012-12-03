using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace SRPServer
{
    internal static class PlayerDatabase
    {
        private static List<PlayerDatabaseEntry> _entries;

        /// <summary>
        /// Finds a player in the database
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public static PlayerDatabaseEntry Find(String username)
        {
            if (_entries == null)
                Load();

            return _entries.FirstOrDefault(entry => entry.Username.ToLower() == username.ToLower());
        }

        /// <summary>
        /// Loads entries from file
        /// </summary>
        public static void Load()
        {
            _entries = new List<PlayerDatabaseEntry>();
            using(BinaryReader fs = new BinaryReader(File.OpenRead("flatdb"))) {
                var count = fs.ReadInt32();
                for (; count > 0; count--)
                    _entries.Add(new PlayerDatabaseEntry()
                    {
                        Username = fs.ReadString(),
                        Verifier = fs.ReadBytes(128),
                        Salt = fs.ReadBytes(10),
                        IsBanned = fs.ReadBoolean()
                    });
            }
        }

        /// <summary>
        /// Saves the database
        /// </summary>
        public static void Save()
        {
            using (BinaryWriter fs = new BinaryWriter(File.OpenWrite("flatdb")))
            {
                fs.Write(_entries.Count);
                foreach (var entry in _entries)
                {
                    fs.Write(entry.Username);
                    fs.Write(entry.Verifier);
                    fs.Write(entry.Salt);
                    fs.Write(entry.IsBanned);
                }
            }
        }

        /// <summary>
        /// Adds an entry
        /// </summary>
        /// <param name="pde"></param>
        public static void Add(PlayerDatabaseEntry pde)
        {
            _entries.Add(pde);
        }
    }
}
