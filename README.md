# linux_nethook_ttl_randomizer

This kernel module takes outgoing TCP packet flows and incoming UDP packet flows
and asigns them a random ttl (between 10 and 127).

To keep track of the flows and their asigned ttl it uses a rudimentary hash table.

TCP flows are deleted from the table when a packet arrives with the FIN flag set,
whereas UDP flows are periodically deleted if they are not active anymore.

Whenever a UDP packet from a certain flow arrives the first bit from the ttl is 
set. This bit is only used to keep track if the flow is active or not. 


  //  Tested on a Lubuntu virtual machine using Virtual Box 6.1.10, running on a Macbook Pro (Late 2013), OS: 10.13.6
	//  The kernel version used to build the model is 5.4.0-26 generic
