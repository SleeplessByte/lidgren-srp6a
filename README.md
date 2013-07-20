lidgren-srp6a
=============

Lidgren SRP-6a implementation that uses a lobby to separate authenticated users from guests.

_What_ is Lidgren / SRP?
-------------
Lidgren is a free super fast, very cool UDP Network library written by Michael Lidgren and available [here][1]. The library is used by a fast number of indie games and other hobby projects. 
	
[1]: http://code.google.com/p/lidgren-network-gen3/ "Lidgren on Google Code"
	
SRP stands for Secure Remote Password protocol and is a way to perform secure remote authentication without an external Certificate Authority (CA). Even if the remote database is compromised, users are not directly exposed in any way. Find more about that [here][2].

[2]: http://srp.stanford.edu/ "The Stanford SRP Homepage"

Lidgren-SRP6a combines the two so SRP is available within any project that uses Lidgren.

_Why_ do I want Lidgren-SRP6a?
-------------
Michael has provided us with a way to encrypt our data, but no way to authenticate in a secure manner. A modified version of this code is being implemented for [my game][3] and since there is a lot of community requesting an implementation I am sharing it. I can not be held responsible for any loss of data, any corruption or any breaking-in whatsoever, but you should be pretty safe taken that you heed the warnings provided.

[3]: http://projectera.org "Epos of Realsm and Aliances"

Can I _Try_ the implementation?
-------------
Start the `SRPServer` project and then start the `SRPClient project`. The addresses are hardcoded (loopback) but comments show you where and how and what. 

By default there is only ONE user allowed access. First try a lot of bogus usernames. Then try a lot of bogus passwords with the user test. Finally login with 
	
	username : test
	password : pass
	
Although I've hidden the password while typing, it will be shown after you submit it for debugging purposes only. The password is NEVER sent over the network. Read [more][2] about SRP if you want to understand how that's possible.

When you are connected, you are allowed to send ONE encrypted message to the server, after which you will be kicked with a simple goodbye.

_How_ do I implement this?
-------------
The code provides a way to separate authenticated users from guest users. Users should connect to your server and be processed by the `NetworkLobby` when they want to authenticate.
I suggest simply letting users connect, receive any updates if needed and then authenticate.

To implement this in your game
* add the `Network.Authentication` Dynamic Link Library (DLL) or project reference to both your server and client. 
* create a `LogonManager` class on your `Server` ONLY
* implement the lookup function in your `LogonManager` (see the interface bewow)
* choose a `keysize` and set it in `NetLobby` (see choices below)
* write code to connect to the server and process any data message by the `NetLobby`

You can see the examples in the example project.
	
Supported Keysizes
--------------
The following keysizes are supported:
* 1024
* 1536
* 2048
* 3072
* 4096

Implemented but not supported yet are
* 6144
* 8192

You can add your own in `NetSRP.Functions`

LogonManager
----------------
Should be a class defined as:

	internal class LogonManager : ILogonManager
		
Should implement the lookup method as:

	public NetBigInteger Lookup(String username, Byte[] data, out Byte[] salt)

Connection Flow
-----------------
C = client
S = server

First connect the normal way 

	> C -> connect request -> S
	> S -> approve connection (optional)
	> C -> receive connection approved

Starts sending/receiving `Messagetype Data`
	
	> C -> authenticate [username : password]
	> C and S process all through NetLobby.IncomingMessage
	> C -> capture NetLobby.OnXXX
	> C -> set a tag on connection
	
When a tag is set, you are authenticated and you can use the secure connection
	
	> C and S Use Lidgren as you would before

