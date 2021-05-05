import sys, iptc, re, socket

accepted_protocols = ['ah','egp','esp','gre','icmp','idp','igmp','ip','pim','pum','pup','raw','rsvp','sctp','tcp','tp','udp']

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
        print(chain.name)
        for rule in chain.rules:
            print(rule.protocol + rule.target.name)
            try:
                chain.delete_rule(rule)
            except:
                all_rules_deleted = False
    if(all_rules_deleted==False):
        print("First Iteration Failed")
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
                print ("==========================================")
                print ("RULE("+ rule_type+")", index, "||", "proto:", rule.protocol + " ||", "src:", rule.src + " ||",
                 "dst:", rule.dst + " ||", "in:", str(rule.in_interface) + " ||", "out:", str(rule.out_interface) + " ||",
                 "Target:", rule.target.name)
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
        chain = iptc.Chain(table, "MYCHAIN")
        deleted = False
        for index, rule in enumerate(chain.rules):
            if(int(rule_number) == index):
                try:
                    chain.delete_rule(rule)
                    print("Rule Successfully Deleted")
                    deleted = True
                except:
                    sys.exit("The rule could not be deleted. Please, try again.")
        if(deleted == False):
            print("The Rule Could Not Be Found")
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
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "MYCHAIN")
            chain.insert_rule(rule)


for index, value in enumerate(sys.argv):
    if(value == '-ip' ):
        match = re.search('^(([0-9]?[0-9]\.)|(1[0-9][0-9]\.)|(2[0-5][0-5]\.)){3}(([0-9]?[0-9])|(1[0-9][0-9])|(2[0-5][0-5]))$', sys.argv[index+1])
        if(match==None):
            sys.exit("The IP address format is incorrect")
        else:
            pass
    elif(value == 'port'):
        if(int(sys.argv[index+1])<65536 and int(sys.argv[index+1])>0):
            pass
        else:
            sys.exit("The specified port is not correct. Please, type a value between 1 and 65535")
    elif(value == 'prot'):
        accepted = False
        for i in accepted_protocols:
            if(i == sys.argv[index+1]):
                accepted = True
            else:
                pass
        if(not accepted):
            sys.exit("The protocol provided is not accepted. The list of accepted protocols is:",'ah',
            'egp','esp','gre','icmp','idp','igmp','ip','pim','pum','pup','raw','rsvp','sctp','tcp','tp','udp')
        #do your job
    elif(value == '-i'):
        available_interface = False
        for i in socket.if_nameindex():
            if(i[1] == sys.argv[index+1]):
                available_interface = True
        if(available_interface == False):
            sys.exit("The selected interface is not available on this system")
        else:
            pass
    elif(value == '-pos'):
        match = re.search('^[0-9]*$', sys.argv[index+1])
        if(match==None):
            sys.exit("Incorrect position format. Please, type an integer >= 0")
        else:
            pass





#chain = iptc.Chain(table, "INPUT")
#for rule in chain.rules:
#	chain.delete_rule(rule)

#rule = iptc.Rule()
#rule.protocol = "tcp"
#rule.target = rule.create_target("DROP")
#chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "MYCHAIN")
#chain.insert_rule(rule)
