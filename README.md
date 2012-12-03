lidgren-srp6a
=============

Lidgren srp6a implementation that uses a lobby to seperate authenticated users from guests.

What?
-------------
Lidgren is a free super fast, very cool UDP Network library written by Michael Lidgren 
and available [here][1]. The libarary is used by a fast number of indie games and other
hobby projects. 
	
[1]: http://code.google.com/p/lidgren-network-gen3/ "Lidgren on Google Code"
	
SRP stands for Secure Remote Password protocol and is a way to perform secure remote
authentication without an external Certificate Authority (CA). Even if the remote database
is compromized, users are not directly exposed in any way. Find more about that [here][2].

[2]: http://srp.stanford.edu/ "The Stanford SRP Homepage"

Why?
-------------
Michael has provided us with a way to encrypt our data, but no way to authenticate in a
secure manner. A modified version of this code is being implented for [my game][3] and 
since there is a lot of community requesting an implementation I am sharing it. Please 
note that I am not responsible for any loss of data or corruption or breakins whatsoever
but you should be pretty safe taken that you heed the warnings provided.

[3]: http://projectera.org "Epos of Realsm and Aliances"

How?
-------------
The code provides a way to seperate authenticated users from guest users. Users should
connect to your server and be processed by the NetworkLobby when they want to authenticate.
I suggest simply letting users connect, receive any updates if needed and then authenticate.

To implement this in your game
* add the Network.Authentication dll or project reference to both your server and client. 
* create a LogonManager on your Serverside ONLY
* implement the lookup function in your logonmanager
* choose a keysize and set it in NetLobby
* write code to connect to the server and process any data message by the networklobby
	
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

You can add your own in NetSRP.Functions

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
	> C \-\> connect request \-\> S
	> S \-\> approve connection (optional)
	> C \-\> receive connection approved

Starts sending/receiving Messagetype Data
	> C \-\> authenticate \[username : password\]
	> C and S process all through NetLobby.IncomingMessage
	> C \-\> capture NetLobby.OnXXX
	> C \-\> set a tag on connection
	
When a tag is set, you are authenticated and you can use the secure connection
	C and S Use lidgren as you would before

