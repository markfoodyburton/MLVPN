# no need for shebang - this file is loaded from charts.d.plugin

# if this chart is called X.chart.sh, then all functions and global variables
# must start with X_

# _update_every is a special variable - it holds the number of seconds
# between the calls of the _update() function
mlvpn_update_every=1

# the priority is used to sort the charts on the dashboard
# 1 = the first chart
mlvpn_priority=150000


# _check is called once, to find out if this chart should be enabled or not
mlvpn_check() {
	# this should return:
	#  - 0 to enable the chart
	#  - 1 to disable the chart
    if [ "`wget -q -O - 127.0.0.1:1040/status | grep "name" -c -m 1`" == '1' ]
    then
        return 0;
    else
        return 1;
    fi
}

# _create is called once, to create the charts
mlvpn_create() {
    # create the chart with 3 dimensions

    
    cat <<EOF
CHART mlvpn.outbound '' "MLVPN Outbound Traffic" "kbits/s" '' '' stacked 1 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." incremental 1 125\n"; }'

    cat <<EOF
CHART mlvpn.outbound_p '' "MLVPN Outbound Traffic breakdown" "%" '' '' stacked 3 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." percentage-of-incremental-row\n"; }'

    cat <<EOF
CHART mlvpn.outbound_w '' "MLVPN Outbound Traffic weight" "%" '' '' stacked 3 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute 1 100\n"; }'

    cat <<EOF
CHART mlvpn.inbound '' "MLVPN Inbound Traffic" "kbits/s" '' '' stacked 2 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." incremental 1 125\n"; }'

    cat <<EOF
CHART mlvpn.inbound_p '' "MLVPN Inbound Traffic Breakdown" "%" '' '' stacked 3 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." percentage-of-incremental-row\n"; }'
    
    cat <<EOF
CHART mlvpn.loss '' "MLVPN loss" "packets/s" '' '' line 7 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}."in ".$i->{"name"}."in absolute 1 1\n"; print  "DIMENSION ".$i->{"name"}."out ".$i->{"name"}."out absolute 1 1\n"; }'

    cat <<EOF
CHART mlvpn.permitted '' "MLVPN permitted" "Mbytes" '' '' line 6 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute 1 1\n"; }'

    cat <<EOF
CHART mlvpn.srtt '' "MLVPN SRTT" "s" '' '' line 4 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute 1 1\n"; }'

#    cat <<EOF
#CHART mlvpn.traffic '' "MLVPN Traffic" "Traffic" '' '' stacked '' ''
#DIMENSION recieved '' absolute 1 1
#EOF

	return 0
}


# _update is called continiously, to collect the values
mlvpn_update() {
	# the first argument to this function is the microseconds since last update
	# pass this parameter to the BEGIN statement (see bellow).

#    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". $i->{"recvbytes"}."\n"; }'

    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;$arg="'$1'";local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};
print "BEGIN mlvpn.inbound $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". $i->{"recvbytes"}."\n"; }
print "END\n";
print "BEGIN mlvpn.inbound_p $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". $i->{"recvbytes"}."\n"; }
print "END\n";
print "BEGIN mlvpn.outbound $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". $i->{"sentbytes"}."\n"; }
print "END\n";
print "BEGIN mlvpn.outbound_p $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". $i->{"sentbytes"}."\n"; }
print "END\n";
print "BEGIN mlvpn.outbound_w $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". (($i->{"weight"})*100.0)."\n"; }
print "END\n";
print "BEGIN mlvpn.loss $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}."in = ". $i->{"lossin"}."\n"; }
foreach $i (@$ts) { print  "SET ".$i->{"name"}."out = ". $i->{"lossout"}."\n"; }
print "END\n";
print "BEGIN mlvpn.permitted $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". $i->{"permitted"}."\n"; }
print "END\n";
print "BEGIN mlvpn.srtt $arg\n";
foreach $i (@$ts) { print  "SET ".$i->{"name"}." = ". $i->{"srtt"}."\n"; }
print "END\n";
'
	return 0
}

#mlvpn_create
#mlvpn_update 42
