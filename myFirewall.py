import sys, iptc, re, socket

single_options = False

predesigned_rules = ['BlockIncomingSSH', 'BlockOutgoingSSH', 'BlockAllSSH', 'BlockIncomingHTTP', 'BlockIncomingHTTPS',\
    'BlockIncomingPing', 'BlockInvalidPackets', 'BlockSYNFlooding', 'BlockXMASAttack', 'ForceSYNPackets'] 

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
custom_position = 0
direction = None

checker = False

############################### List of Predefined Rules #############################


def block_incoming_ssh():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.dport = "22"
    match = rule.create_match("state")
    match.state = "NEW"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def block_outgoing_ssh():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.dport = "22"
    match = rule.create_match("state")
    match.state = "NEW"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def block_all_ssh():
    chain1 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain2 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.dport = "22"
    match = rule.create_match("state")
    match.state = "NEW"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain1.insert_rule(rule)
    chain2.insert_rule(rule)
    print("Successfully Created")

def block_incoming_http():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.dport = "80"
    match = rule.create_match("state")
    match.state = "NEW"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def block_incoming_https():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.dport = "443"
    match = rule.create_match("state")
    match.state = "NEW"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def block_incoming_ping():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.protocol = "icmp"
    match = rule.create_match("icmp")
    match.icmp_type = "echo-reply"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def block_invalid_packets():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    match = rule.create_match("state")
    match.state = "iNVALID"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def syn_flooding():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.tcp_flags = [ 'FIN,SYN,RST,ACK', 'SYN' ]
    match = rule.create_match("limit")
    match.limit = "10/second"
    target = iptc.Target(rule, "ACCEPT")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def block_xmas_attack():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.tcp_flags = [ 'ALL', 'ALL' ]
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

def force_syn_packets():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.protocol = "tcp"
    match = rule.create_match("tcp")
    match.syn = "!1"
    match = rule.create_match("state")
    match.state = "NEW"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)
    print("Successfully Created")

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

# Function to delete a single rule

def delete_rule(rule, table, direction = None):

    if(direction == 'input'):
        chain = iptc.Chain(table, "INPUT")
        deleted1 = False
        for index, rule in enumerate(chain.rules):
            if(int(rule_number) == index):
                try:
                    chain.delete_rule(rule)
                    print("Rule Successfully Deleted for Input")
                    deleted1 = True
                except:
                    sys.exit("The rule could not be deleted for Input. Please, try again.")
        if(deleted1 == False):
            print("The Rule Could Not Be Found for Input")

    elif (direction == 'output'):
        chain = iptc.Chain(table, "OUTPUT")
        deleted1 = False
        for index, rule in enumerate(chain.rules):
            if(int(rule_number) == index):
                try:
                    chain.delete_rule(rule)
                    print("Rule Successfully Deleted for Output")
                    deleted1 = True
                except:
                    sys.exit("The rule could not be deleted for Input. Please, try again.")
        if(deleted1 == False):
            print("The Rule Could Not Be Found for Output")

    else:
        sys.exit("Delete rule function error. Incorrect parameter")

# First check, for options that should be used alone

for index, value in enumerate(sys.argv):

    if(value == '-l' ):
        if (len(sys.argv)) != 2:
            sys.exit("The option -l does not accept additional options. Please, type: myFirewall -l")
        single_options = True
        table = iptc.Table(iptc.Table.FILTER)
        for chain in table.chains:
            #print ("Chain ",chain.name)
            rule_type = chain.name[:3]
            for index, rule in enumerate(chain.rules):
                dport = None
                sport = None
                ip_src_range = None
                ip_dst_range = None
                match_state = None
                match_tcp_flags = None
                for match in rule.matches:
                    if (match.dport != None):
                        dport = match.dport
                    if (match.sport != None):
                        sport = match.sport
                    if (match.src_range != None):
                        ip_src_range = match.src_range
                    if (match.dst_range != None):
                        ip_dst_range = match.dst_range
                    if (match.state != None):
                        match_state = match.state
                    if (match.tcp_flags != None):
                        match_tcp_flags = match.tcp_flags[match.tcp_flags.find(' ')+1:]
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
                 "dport:", str(dport) + " ||", "src:", source_ip + " ||", "dst:", destination_ip + " ||\n", "|| inInt:",
                 str(rule.in_interface) + " ||", "outInt:", str(rule.out_interface) + " ||",
                 "tcpflags:", str(match_tcp_flags) + " ||", "state:", str(match_state) + " ||", "Target:", rule.target.name)
                print ("==========================================")

    elif(value == '-r'):
        if (len(sys.argv)) != 2:
            sys.exit("The option -r does not accept additional options. Please, type: myFirewall -r")
        single_options = True
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
        if (len(sys.argv) != 3 and len(sys.argv) != 4):
            sys.exit("The option -d does not accept these options. Please, type: myFirewall -d RuleNumer [-in|-out]")
        single_options = True
        table = iptc.Table(iptc.Table.FILTER)
        rule_number = sys.argv[2]
        if(len(sys.argv) == 4):
            if (sys.argv[3] == '-in'):
                delete_rule(rule_number, table, direction = 'input')
            elif (sys.argv[3] == '-out'):
                delete_rule(rule_number, table, direction = 'output')
            else:
                sys.exit("Incorrect parameter. Please, type: myFirewall -d RuleNumer [-in|-out]")
        else:
            delete_rule(rule_number, table, direction = 'input')
            delete_rule(rule_number, table, direction = 'output')
        #for chain in table.chains:
            #for rule in chain.rules:
            #    chain.delete_rule(rule)

    elif(value == '-all'):
        if ((len(sys.argv) != 3) and (sys.argv[index+1]!='ACCEPT') and (sys.argv[index+1]!='DROP')):
            sys.exit("The -all option lets the user to ACCEPT or DROP all packets, independently of ports,"+\
            " protocols or IPs. Please, specify a ACCEPT or DROP argument")
        else:
            single_options = True
            rule = iptc.Rule()
            rule.target = rule.create_target(sys.argv[index+1])
            chain1 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain2 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain1.insert_rule(rule)
            chain2.insert_rule(rule)

    elif(value == '-rule'):
        single_options = True
        if (len(sys.argv)) != 3:
            if (len(sys.argv) == 2):
                print("The list of rules available is:\n")
                for i in predesigned_rules:
                    print(i)
            else:
                sys.exit("The option -r does not accept additional options. Please, type: -rule RULE")
        elif(sys.argv[index+1] == 'BlockIncomingSSH'):
            block_incoming_ssh()
        elif(sys.argv[index+1] == 'BlockOutgoingSSH'):
            block_outgoing_ssh()
        elif(sys.argv[index+1] == 'BlockAllSSH'):
            block_all_ssh()
        elif(sys.argv[index+1] == 'BlockIncomingHTTP'):
            block_incoming_http()
        elif(sys.argv[index+1] == 'BlockIncomingHTTPS'):
            block_incoming_https()
        elif(sys.argv[index+1] == 'BlockIncomingPing'):
            block_incoming_ping()
        elif(sys.argv[index+1] == 'BlockInvalidPackets'):
            block_invalid_packets()
        elif(sys.argv[index+1] == 'BlockSYNFlooding'):
            syn_flooding()
        elif(sys.argv[index+1] == 'BlockXMASAttack'):
            block_xmas_attack()
        elif(sys.argv[index+1] == 'ForceSYNPackets'):
            force_syn_packets()
        else:
            print("Rule not available. The list of available rules is:\n")   
            for i in predesigned_rules:
                print(i) 
            print("")                     
    


if(not single_options):
    # Iterator to retrieve all information and create a Rule
    for index, value in enumerate(sys.argv):

        if(value == '-ipsrc'):
            match_single = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
            match_range = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))-(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
            if((match_single==None) and (match_range==None)):
                sys.exit("The IP address format is incorrect")
            else:
                checker = True
                if(match_single!=None):
                    ipsrc = sys.argv[index+1]
                if(match_range!=None):
                    ipsrc_range = sys.argv[index+1]

        elif(value == '-ipdst'):
            match_single = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
            match_range = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))-(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
            if(match_single==None and match_range==None):
                sys.exit("The IP address format is incorrect")
            else:
                checker = True
                if(match_single!=None):
                    ipdst = sys.argv[index+1]
                if(match_range!=None):
                    ipdst_range = sys.argv[index+1]

        elif(value == '-portsrc'):
            match_single = re.search('^[0-9]+$', sys.argv[index+1])
            match_range = re.search('^[0-9]+:[0-9]+$', sys.argv[index+1])
            if(match_single==None and match_range==None):
                sys.exit("The Port/Port range format is incorrect")
            checker = True
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
            checker = True
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
            checker = True

        elif(value == '-intin'):
            available_interface = False
            for i in socket.if_nameindex():
                if(i[1] == sys.argv[index+1]):
                    available_interface = True
            if(available_interface == False):
                sys.exit("The selected interface is not available on this system")
            else:
                interfacein = sys.argv[index+1]
            checker = True

        elif(value == '-intout'):
            available_interface = False
            for i in socket.if_nameindex():
                if(i[1] == sys.argv[index+1]):
                    available_interface = True
            if(available_interface == False):
                sys.exit("The selected interface is not available on this system")
            else:
                interfaceout = sys.argv[index+1]
            checker = True

        elif(value == '-pos'):
            match = re.search('^[0-9]*$', sys.argv[index+1])
            if(match==None):
                sys.exit("Incorrect position format. Please, type an integer >= 0")
            else:
                custom_position = sys.argv[index+1]
            checker = True

        elif(value == '-t'):
            if(sys.argv[index+1] == "ACCEPT"):
                target = "ACCEPT"
            elif(sys.argv[index+1] == "DROP"):
                target = "DROP"
            else:
                sys.exit('Incorrect target option. Please, choose between "ACCEPT" and "DROP"')
            checker = True

        elif(value == '-in'):
            direction = 'incoming'

        elif(value == '-out'):
            direction = 'outgoing'
        else:
            if(checker == True or index==0):
                checker = False
            else:
                sys.exit("Incorrect option: " + value)


    rule = iptc.Rule()

    if(ipsrc != None):
        rule.src = ipsrc

    if(ipsrc_range != None or ipdst_range != None): 
        match = rule.create_match("iprange")
        if(ipsrc_range != None):
            match.src_range = ipsrc_range
        else:
            match.dst_range = ipdst_range

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

    if(portsrc_range != None or portdst_range != None):
        if(protocol == None):
            protocol = "tcp"
            rule.protocol = protocol
            match = rule.create_match(protocol)
        if(portsrc_range != None):
            match.sport = portsrc_range
        if(portdst_range != None):
            match.dport = portdst_range

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
        try:
            chain1.insert_rule(rule, position=int(custom_position))
        except:
            sys.exit("Index of insertion out of boundaries for existing Input table. Please, choose a value between 0 and (Max.AmountOfRules-1)")
        try:
            chain2.insert_rule(rule, position=int(custom_position))
        except:
            sys.exit("Index of insertion out of boundaries for Output table. Please, choose a value between 0 and (Max.AmountOfRules-1)")

    elif(direction == "incoming"):
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        try:
            chain.insert_rule(rule, position=int(custom_position))
        except:
            sys.exit("Index of insertion out of boundaries.  Please, choose a value between 0 and (Max.AmountOfRules-1)")

    elif(direction == "outgoing"):
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
        try:
            chain.insert_rule(rule, position=int(custom_position))
        except:
            sys.exit("Index of insertion out of boundaries. Please, choose a value between 0 and (Max.AmountOfRules-1)")
