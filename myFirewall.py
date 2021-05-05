import sys, iptc, re, socket

accepted_protocols = ['ah','egp','esp','gre','icmp','idp','igmp','ip','pim','pum','pup','raw','rsvp','sctp','tcp','tp','udp']
ipsrc = None
ipsrc_range = None
ipdst = None
ipdst_range = None
portsrc = None
portsrc_range = None
portdst = None
portdst_range = None
protocol = None
interfacein = None
interfaceout = None
target = None
position = None
direction = None

# Code to create our custom chain inside the Filter table
already_created = False
table = iptc.Table(iptc.Table.FILTER)
for chain in table.chains:
	if chain.name == "MYCHAIN":
		already_created = True
		# Custom Table already created.
	else:
		pass

if not already_created:
	table.create_chain("MYCHAIN")
#table.delete_chain("MYCHAIN")

# Function to delete rules
all_rules_deleted = True
def delete_rules(table):
    global all_rules_deleted
    all_rules_deleted = True
    for chain in table.chains:
        #print(chain.name)
        for rule in chain.rules:
            try:
                chain.delete_rule(rule)
                print(rule.protocol, rule.src, rule.dst, rule.target.name, "is DELETED")
            except:
                all_rules_deleted = False
    if(all_rules_deleted==False):
        #print("First Iteration Failed")
        delete_rules(table)

# First check, for options that should be used alone
for index, value in enumerate(sys.argv):
    if(value == '-l' ):
        if (len(sys.argv)) != 2:
            sys.exit("The option -l does not accept additional options. Please, type: myFirewall -l")
        table = iptc.Table(iptc.Table.FILTER)
        for chain in table.chains:
            #print ("Chain ",chain.name)
            rule_type = chain.name[:3]
            for index, rule in enumerate(chain.rules):
                dport = None
                sport = None
                ip_src_range = None
                ip_dst_range = None
                for match in rule.matches:
                    if (match.dport != None):
                        dport = match.dport
                    if (match.sport != None):
                        sport = match.sport
                    if (match.src_range != None):
                        ip_src_range = match.src_range
                    if (match.dst_range != None):
                        ip_dst_range = match.dst_range
                if(ip_src_range != None):
                    source_ip = ip_src_range
                else:
                    source_ip = rule.src
                if(ip_dst_range != None):
                    destination_ip = ip_dst_range
                else:
                    destination_ip = rule.dst
                print ("==========================================")
                print ("RULE("+ rule_type+")", index, "||", "proto:", rule.protocol + " ||", "sport:", str(sport) + " ||",
                 "dport:", str(dport) + " ||", "src:", source_ip + " ||", "dst:", destination_ip + " ||\n", "|| in:",
                 str(rule.in_interface) + " ||", "out:", str(rule.out_interface) + " ||","Target:", rule.target.name)
                print ("==========================================")
    elif(value == '-r'):
        if (len(sys.argv)) != 2:
            sys.exit("The option -r does not accept additional options. Please, type: myFirewall -r")
        table1 = iptc.Table(iptc.Table.FILTER)
        delete_rules(table1)
        table2 = iptc.Table(iptc.Table.MANGLE)
        delete_rules(table2)
        table3 = iptc.Table(iptc.Table.NAT)
        delete_rules(table3)
        table4 = iptc.Table(iptc.Table.RAW)
        delete_rules(table4)
        table5 = iptc.Table(iptc.Table.SECURITY)
        delete_rules(table5)
    elif(value == '-d'):
        if (len(sys.argv) != 3):
            sys.exit("The option -d does not accept additional options. Please, type: myFirewall -d RuleNumer")
        rule_number = sys.argv[2]
        table = iptc.Table(iptc.Table.FILTER)
        chain1 = iptc.Chain(table, "INPUT")
        deleted1 = False
        for index, rule in enumerate(chain1.rules):
            if(int(rule_number) == index):
                try:
                    chain1.delete_rule(rule)
                    print("Rule Successfully Deleted for Input")
                    deleted1 = True
                except:
                    sys.exit("The rule could not be deleted for Input. Please, try again.")
        if(deleted1 == False):
            print("The Rule Could Not Be Found for Input")
        chain2 = iptc.Chain(table, "OUTPUT")
        deleted2 = False
        for index, rule in enumerate(chain2.rules):
            if(int(rule_number) == index):
                try:
                    chain2.delete_rule(rule)
                    print("Rule Successfully Deleted for Output")
                    deleted2 = True
                except:
                    sys.exit("The rule could not be deleted for Output. Please, try again.")
        if(deleted2 == False):
            print("The Rule Could Not Be Found for Output")
        #for chain in table.chains:
            #for rule in chain.rules:
            #    chain.delete_rule(rule)
    elif(value == '-all'):
        if ((len(sys.argv) != 3) and (sys.argv[index+1]!='ACCEPT') and (sys.argv[index+1]!='DROP')):
            sys.exit("The -all option lets the user to ACCEPT or DROP all packets, independently of ports,"+\
            " protocols or IPs. Please, specify a ACCEPT or DROP argument")
        else:
            rule = iptc.Rule()
            rule.target = rule.create_target(sys.argv[index+1])
            chain1 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain2 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain1.insert_rule(rule)
            chain2.insert_rule(rule)


for index, value in enumerate(sys.argv):
    if(value == '-ipsrc'):
        match_single = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
        match_range = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))-(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
        if((match_single==None) and (match_range==None)):
            sys.exit("The IP address format is incorrect")
        else:
            if(match_single!=None):
                ipsrc = sys.argv[index+1]
            if(match_range!=None):
                ipsrc_range = sys.argv[index+1]
    elif(value == '-ipdst'):
        match_single = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
        match_range = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))\
            -(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
        if(match_single==None and match_range==None):
            sys.exit("The IP address format is incorrect")
        else:
            if(match_single!=None):
                ipdst = sys.argv[index+1]
            if(match_range!=None):
                ipdst_range = sys.argv[index+1]
    elif(value == '-portsrc'):
        match_single = re.search('^[0-9]+$', sys.argv[index+1])
        match_range = re.search('^[0-9]+:[0-9]+$', sys.argv[index+1])
        if(match_single==None and match_range==None):
            sys.exit("The Port/Port range format is incorrect")
        if(match_single != None):
            if(int(sys.argv[index+1])<65536 and int(sys.argv[index+1])>0):
                portsrc = sys.argv[index+1]
            else:
                sys.exit("The specified port is out of the boundaries. Please, type a value between 1 and 65535")
        elif(match_range != None):
            first_port_group = int(sys.argv[index+1][:sys.argv[index+1].find(':')])
            second_port_group = int(sys.argv[index+1][sys.argv[index+1].find(':')+1:])
            if(((first_port_group<65536) and (first_port_group>0) and (second_port_group<65536) and (second_port_group>0))):
                portsrc_range = sys.argv[index+1]
            else:
                sys.exit("The specified port range is out of the boundaries. Please, type values between 1 and 65535")
        else:
            sys.exit("Port incorrectly parsed")
    elif(value == '-portdst'):
        match_single = re.search('^[0-9]+$', sys.argv[index+1])
        match_range = re.search('^[0-9]+:[0-9]+$', sys.argv[index+1])
        if(match_single==None and match_range==None):
            sys.exit("The Port/Port range format is incorrect")
        if(match_single != None):
            if(int(sys.argv[index+1])<65536 and int(sys.argv[index+1])>0):
                portdst = sys.argv[index+1]
            else:
                sys.exit("The specified port is out of the boundaries. Please, type a value between 1 and 65535")
        elif(match_range != None):
            first_port_group = int(sys.argv[index+1][:sys.argv[index+1].find(':')])
            second_port_group = int(sys.argv[index+1][sys.argv[index+1].find(':')+1:])
            if(((first_port_group<65536) and (first_port_group>0) and (second_port_group<65536) and (second_port_group>0))):
                portdst_range = sys.argv[index+1]
            else:
                sys.exit("The specified port range is out of the boundaries. Please, type values between 1 and 65535")
        else:
            sys.exit("Port incorrectly parsed")
    elif(value == '-proto'):
        accepted = False
        for i in accepted_protocols:
            if(i == sys.argv[index+1]):
                accepted = True
            else:
                protocol = sys.argv[index+1]
        if(not accepted):
            sys.exit("The protocol provided is not accepted. The list of accepted protocols is:",'ah',
            'egp','esp','gre','icmp','idp','igmp','ip','pim','pum','pup','raw','rsvp','sctp','tcp','tp','udp')
    elif(value == '-intin'):
        available_interface = False
        for i in socket.if_nameindex():
            if(i[1] == sys.argv[index+1]):
                available_interface = True
        if(available_interface == False):
            sys.exit("The selected interface is not available on this system")
        else:
            interfacein = sys.argv[index+1]
    elif(value == '-intout'):
        available_interface = False
        for i in socket.if_nameindex():
            if(i[1] == sys.argv[index+1]):
                available_interface = True
        if(available_interface == False):
            sys.exit("The selected interface is not available on this system")
        else:
            interfaceout = sys.argv[index+1]
    elif(value == '-pos'):
        match = re.search('^[0-9]*$', sys.argv[index+1])
        if(match==None):
            sys.exit("Incorrect position format. Please, type an integer >= 0")
        else:
            position = sys.argv[index+1]
    elif(value == '-t'):
        if(sys.argv[index+1] == "ACCEPT"):
            target = "ACCEPT"
        elif(sys.argv[index+1] == "DROP"):
            target = "DROP"
        else:
            sys.exit('Incorrect target option. Please, choose between "ACCEPT" and "DROP"')
    elif(value == '-in'):
        direction = 'incoming'
    elif(value == '-out'):
        direction = 'outgoing'

# chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
# rule = iptc.Rule()
# rule.dst = "192.168.1.2"
# rule.protocol = "udp"
# match = iptc.Match(rule, "udp")
# match.dport = "1234"
# rule.add_match(match)
# target = iptc.Target(rule, "DROP")
# rule.target = target
# chain.insert_rule(rule)



rule = iptc.Rule()

if(ipsrc != None):
    rule.src = ipsrc
if(ipsrc_range != None or ipdst_range != None): 
    match = rule.create_match("iprange")
    if(ipsrc_range != None):
        match.src_range = ipsrc_range
    else:
        match.dst_range = ipdst_range
    #rule.add_match(match)
if(ipdst != None):
    rule.dst = ipdst
if(protocol != None):
    rule.protocol = protocol
    if(protocol == "tcp" or protocol == "udp"):
        match = rule.create_match(protocol)
if(portsrc != None or portdst != None):
    if(protocol == None):
        protocol = "tcp"
        rule.protocol = protocol
        match = rule.create_match(protocol)
    if(portsrc != None):
        match.sport = portsrc
    if(portdst != None):
        match.dport = portdst
    #rule.add_match(match)
if(portsrc_range != None or portdst_range != None):
    if(protocol == None):
        protocol = "tcp"
        rule.protocol = protocol
        match = rule.create_match(protocol)
    if(portsrc_range != None):
        match.sport = portsrc_range
    if(portdst_range != None):
        match.dport = portdst_range
    #rule.add_match(match)
if(interfacein != None):
    rule.in_interface = interfacein
if(interfaceout != None):
    rule.out_interface = interfaceout

if(target != None):
    rule.target = rule.create_target(target)
else:
    sys.exit('You must specify a target: -t "ACCEPT" or -t "DROP"')

if(direction == None):
    chain1 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain2 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    chain1.insert_rule(rule)
    chain2.insert_rule(rule)
elif(direction == "incoming"):
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)
elif(direction == "outgoing"):
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    chain.insert_rule(rule)




#chain = iptc.Chain(table, "INPUT")
#for rule in chain.rules:
#	chain.delete_rule(rule)

# rule = iptc.Rule()
# rule.protocol = "tcp"
# rule.target = rule.create_target("DROP")
# match = rule.create_match("tcp")
# match.dport = "81"
# match.sport = "201"
# chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
# chain.insert_rule(rule)
