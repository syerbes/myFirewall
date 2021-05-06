myFirewall
======

**myFirewall**, A customizable Firewall for Linux based systems tool written in python


Detailed Information
--------------------

myFirewall is a python based tool which provides the user with a set of options to properly configure Firewall rules for Linux systems.
More specifically, rules can be created with the most common configurable features: protocol, port, interface, tcp-flags, etc.
It also incorporates an option for the user to select typical rules from a list, with effective protection against a variety type of potential breaches,
reaching out both type of users: beginner or advanced. Furthermore, it has a strict input validation to ensure that a rule is properly formatted before
being included into the system.

Based on the Iptables native linux firewall, it contributes with the following additional features:
	
	- Easier to use. More user friendly for beginners. It incorporates the most important features to configure rules.
	- Predefined rules to defend the system against known attacks and potential breaches.
	- Strict input validation with clear explanations in case of wrong inputs.




Installation (Ubuntu)
------------

There are two main dependencies to be installed:

	Iptables - A command-line native firewall commonly included with the operating system. If not, it can be easily installed with: 
		'sudo apt-get install iptables'
	
	python-iptables - A python module to interact with Iptables.
		'pip install --upgrade python-iptables'

Usage
-----

    :~$ python3 myFirewall.py -all ACCEPT|DROP [-in|-out]
    :~$ python3 myFirewall.py -d RuleNumber [-in|-out]
    :~$ python3 myFirewall.py -l
    :~$ python3 myFirewall.py -r
    :~$ python3 myFirewall.py -rule RuleName
    :~$ python3 myFirewall.py [OPTIONS]
    
    Example:	python3 myFirewall.py -rule BlockIncomingSSH
    		python3 myFirewall.py -proto tcp -portdst 4678 -out -t ACCEPT
    		python3 myFirewall.py -proto tcp -ipsrc 45.32.2.1-45.34.0.0 -ipdst 122.123.22.1 -pos 1 -t DROP
    
     Commands:
      -all  ACCEPT|DROP	Accept or block all packets. The option -in|-out specifies incoming of outgoing traffic. By default, it includes both
      -d	RuleNumber	Delete the rule given an ID number. The ID is shown in option -l. By default, it deletes the rule from both incoming and outgoing.
      -l			List all the rules.
      -r			Delete all rules in the system.
      -rule	RuleName	Creates a rule based on RuleName:
      
      		
     	RuleNames:
     	
    	  BlockIncomingSSH	Block all incoming SSH new requests. It does not block existing sessions.
    	  BlockOutgoingSSH	Block all outgoing SSH new requests. It does not block existing sessions.
    	  BlockAllSSH		Block all SSH traffic.
    	  BlockIncomingHTTP	Block incoming HTTP new requests.
    	  BlockIncomingHTTPS	Block incoming HTTPS new requests.
    	  BlockIncomingPing	Block incoming Ping echo-requests packets. It allows echo-replies.
    	  BlockInvalidPackets	Block invalid state packets that not belong to any connection.
    	  BlockSYNFlooding	Block the SYN flooding attack, by controlling the amount of SYN packets received per time unit.
    	  BlockXMASAttack	Block XMAS attack, or packets with all TCP flags set to 1. This type of attack takes many resources from the server.
    	  ForceSYNPackets	Force all incoming TCP connections to be SYN, and refuse any other TCP flag.
    	  
     Options:
      -in|out			Specifies if the command is applied to incomming traffic or outgoing traffic. If not defined, it is applied to both.
      -ipsrc,			Ip Source. It can be a single value or a range: xxx.xxx.xxx.xxx OR xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx
      -ipdst,			Ip Destination. It can be a single value or a range: xxx.xxx.xxx.xxx OR xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx
      -portsrc,			Source port. It can be a single value or a range: x OR x:x
      -portdst,			Destination port. It can be a single value or a range: x OR x:x
      -pos,				Position to store the rule. Positions are important in terms of priority. If not icluded, the default position is the first (0).
      -proto,			Protocol. It can be: 'ah','egp','esp','gre','icmp','idp','igmp','ip','pim','pum','pup','raw','rsvp','sctp','tcp','tp','udp'.
      -intin,			Interface for incoming traffic.
      -intout,			Interface for outgoing traffic.
      -t				Target. It can be ACCEPT or DROP. Always needed when creating a rule.

  

Copyright/ License/ Credits
---------------------------

Copyright 2021 Sergio Yerbes Martinez

This is free software.
