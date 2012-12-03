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
is compromized, users are not directly exposed in any way. Find more about that [here][2]

	[2]: http://srp.stanford.edu/ "The Stanford SRP Homepage"