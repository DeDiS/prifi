#!/usr/bin/env bash


# ************************************
# PriFi all-in-one startup script
# ************************************
# author : Ludovic Barman
# email : ludovic.barman@gmail.com
# belongs to : the PriFi project
# 			<github.com/lbarman/prifi>
# ************************************

# variables that you might change often

dbg_lvl=3                       # 1=less verbose, 3=more verbose. goes up to 5, but then prints the SDA's message (network framework)
try_use_real_identities="false" # if "true", will try to use "self-generated" public/private key as a replacement for the dummy keys
                                # we generated for you. It asks you if it does not find real keys. If false, will always use the dummy keys.
colors="true"                   # if  "false", the output of PriFi (and this script) will be in black-n-white

socksServer1Port=8080           # the port for the SOCKS-Server-1 (part of the PriFi client)
socksServer2Port=8090           # the port to attempt connect to (from the PriFi relay) for the SOCKS-Server-2
                                # notes : see <https://github.com/lbarman/prifi/blob/master/README_architecture.md>

all_localhost_n_clients=3      # number of clients to start in the "all-localhost" script

# default file names :

prifi_file="prifi.toml"                     # default name for the prifi config file (contains prifi-specific settings)
identity_file="identity.toml"               # default name for the identity file (contains public + private key)
group_file="group.toml"                     # default name for the group file (contains public keys + address of other nodes)

# location of the buildable (go build) prifi file :

bin_file="$GOPATH/src/github.com/lbarman/prifi/sda/app/prifi.go"

# we have two "identities" directory. The second one is empty unless you generate your own keys with "gen-id"

configdir="config"
defaultIdentitiesDir="identities_default"   # in $configdir
realIdentitiesDir="identities_real"         # in $configdir

# min required go version
min_go_version=17                           # min required go version, without the '.', e.g. 17 for 1.7.x

# unimportant variable (but do not change, ofc)

sleeptime_between_spawns=1                  # time in second between entities launch in all-localhost part
cothorityBranchRequired="v1.0"              # the branch required for the cothority (SDA) framework

#pretty colored message
highlightOn="\033[33m"
highlightOff="\033[0m"
shell="\033[35m[script]${highlightOff}"
warningMsg="${highlightOn}[warning]${highlightOff}"
errorMsg="\033[31m\033[1m[error]${highlightOff}"
okMsg="\033[32m[ok]${highlightOff}"
if [ "$colors" = "false" ]; then
	highlightOn=""
	highlightOff=""
	shell="[script]"
	warningMsg="[warning]"
	errorMsg="[error]"
	okMsg="[ok]"
fi

# ------------------------
#     HELPER FUNCTIONS
# ------------------------

print_usage() {
	echo
	echo -e "PriFi, a tracking-resistant protocol for local-area anonymity"
	echo
	echo -e "Usage: run-prifi.sh ${highlightOn}role/operation [params]${highlightOff}"
	echo -e "	${highlightOn}role${highlightOff}: client, relay, trustee"
	echo -e "	${highlightOn}operation${highlightOff}: install, sockstest, all-localhost, gen-id, integration-test, simul, simul-get-logs, simul-clear-logs"
	echo -e "	${highlightOn}params${highlightOff} for role ${highlightOn}relay${highlightOff}: [socks_server_port] (optional, numeric)"
	echo -e "	${highlightOn}params${highlightOff} for role ${highlightOn}trustee${highlightOff}: id (required, numeric)"
	echo -e "	${highlightOn}params${highlightOff} for role ${highlightOn}client${highlightOff}: id (required, numeric), [prifi_socks_server_port] (optional, numeric)"
	echo -e "	${highlightOn}params${highlightOff} for operation ${highlightOn}install${highlightOff}: none"
	echo -e "	${highlightOn}params${highlightOff} for operation ${highlightOn}all-localhost${highlightOff}: none"
	echo -e "	${highlightOn}params${highlightOff} for operation ${highlightOn}gen-id${highlightOff}: none"
	echo -e "	${highlightOn}params${highlightOff} for operation ${highlightOn}sockstest${highlightOff}: [socks_server_port] (optional, numeric), [prifi_socks_server_port] (optional, numeric)"
	echo -e "	${highlightOn}params${highlightOff} for operation ${highlightOn}simul${highlightOff}: none"
	echo -e "	${highlightOn}params${highlightOff} for operation ${highlightOn}simul-get-logs${highlightOff}: none"
	echo -e "	${highlightOn}params${highlightOff} for operation ${highlightOn}simul-clear-logs${highlightOff}: none"
	echo

	echo -e "Man-page:"
	echo -e "	${highlightOn}install${highlightOff}: get the dependencies, and tests the setup"
	echo -e "	${highlightOn}relay${highlightOff}: starts a PriFi relay"
	echo -e "	${highlightOn}trustee${highlightOff}: starts a PriFi trustee, using the config file trustee${highlightOn}id${highlightOff}"
	echo -e "	${highlightOn}client${highlightOff}: starts a PriFi client, using the config file client${highlightOn}id${highlightOff}"
	echo -e "	${highlightOn}all-localhost${highlightOff}: starts a Prifi relay, a trustee, three clients all on localhost"
	echo -e "	${highlightOn}sockstest${highlightOff}: starts the PriFi and non-PriFi SOCKS tunnel, without PriFi anonymization"
	echo -e "	${highlightOn}gen-id${highlightOff}: interactive creation of identity.toml"
	echo -e "	${highlightOn}integration-test${highlightOff}: runs all-localhost and test if the relay manages to communicate"
	echo -e "	${highlightOn}simul${highlightOff}: runs the simulation specified in sda/simulation/prifi_simul.toml in localhost/on Deterlab"
	echo -e "	${highlightOn}simul-get-logs${highlightOff}: fetches the logs from the user server in Deterlab"
	echo -e "	${highlightOn}simul-clear-logs${highlightOff}: clears the logs in the user server in Deterlab"
	echo -e "	Lost ? read https://github.com/lbarman/prifi/README.md"
}

#tests if GOPATH is set and exists
test_go(){
	if [ -z "$GOPATH"  ]; then
		echo -e "$errorMsg GOPATH is unset ! make sure you installed the Go language."
		exit 1
	fi
	if [ ! -d "$GOPATH"  ]; then
		echo -e "$errorMsg GOPATH ($GOPATH) is not a folder ! make sure you installed the Go language correctly."
		exit 1
	fi
	GO_VER=$(go version 2>&1 | sed 's/.*version go\(.*\)\.\(.*\)\ \(.*\)/\1\2/; 1q')
	GO_VER=18
	if [ "$GO_VER" -lt "$min_go_version" ]; then
		echo -e "$errorMsg Go >= 1.7.0 is required"
		exit 1
	fi
}

# tests if the cothority exists and is on the correct branch
test_cothority() {
	branchOk=$(cd "$GOPATH/src/gopkg.in/dedis/onet.v1"; git status | grep "On branch $cothorityBranchRequired" | wc -l)

	if [ "$branchOk" -ne 1 ]; then
		echo -e "$errorMsg Make sure \"$GOPATH/src/gopkg.in/dedis/onet.v1\" is a git repo, on branch \"$cothorityBranchRequired\". Try running \"./prifi.sh install\""
		exit 1
	fi
}

# test if $1 is a digit, if not, prints "argument $2 invalid" and exit.
test_digit() {
	case $1 in
		''|*[!0-9]*)
			echo -e "$errorMsg parameter $2 need to be an integer."
			exit 1;;
		*) ;;
	esac
}

#test if all the files we need are there.
test_files() {

	if [ ! -f "$bin_file" ]; then
		echo -e "$errorMsg Runnable go file does not seems to exists: $bin_file"
		exit
	fi

	if [ ! -f "$identity_file2" ]; then
		echo -e "$errorMsg Cothority config file does not exist: $identity_file2"
		exit
	fi

	if [ ! -f "$group_file2" ]; then
		echo -e "$errorMsg Cothority group file does not exist: $group_file2"
		exit
	fi

	if [ ! -f "$prifi_file2" ]; then
		echo -e "$errorMsg PriFi config file does not exist: $prifi_file2"
		exit
	fi
}

# ------------------------
#     MAIN SWITCH
# ------------------------

# $1 is operation : "install", "relay", "client", "trustee", "sockstest", "all-localhost", "clean", "gen-id"
case $1 in

	install|Install|INSTALL)

		echo -n "Testing for GO... "
		test_go
		echo -e "$okMsg"

		echo -n "Getting all go packages... "
		cd sda/app; go get ./... 1>/dev/null 2>&1
		cd ../..
		echo -e "$okMsg"

		echo -en "Switching ONet branch to ${highlightOn}$cothorityBranchRequired${highlightOff}... "
		cd "$GOPATH/src/gopkg.in/dedis/onet.v1"; git checkout "$cothorityBranchRequired" 1>/dev/null 2>&1
		echo -e "$okMsg"

		echo -n "Re-getting all go packages (since we switched branch)... "
		cd "$GOPATH/src/github.com/lbarman/prifi/sda/app"; go get ./... 1>/dev/null 2>&1
		cd ../..
		cd "$GOPATH/src/gopkg.in/dedis/onet.v1"; go get -u ./... 1>/dev/null 2>&1
		echo -e "$okMsg"

		echo -n "Testing ONet branch... "
		test_cothority
		echo -e "$okMsg"

		;;

	relay|Relay|RELAY)

		#test for proper setup
		test_go
		test_cothority

		# the 2nd argument can replace the port number
		if [ "$#" -eq 2 ]; then
			test_digit "$2" 2
			socksServer2Port="$2"
		fi

		#specialize the config file (we use the dummy folder, and maybe we replace with the real folder after)
		prifi_file2="$configdir/$prifi_file"
		identity_file2="$configdir/$defaultIdentitiesDir/relay/$identity_file"
		group_file2="$configdir/$defaultIdentitiesDir/relay/$group_file"

		#we we want to, try to replace with the real folder
		if [ "$try_use_real_identities" = "true" ]; then
			if [ -f "$configdir/$realIdentitiesDir/relay/$identity_file" ] && [ -f "$configdir/$defaultIdentitiesDir/relay/$group_file" ]; then
				echo -e "$okMsg Found real identities (in $configdir/$realIdentitiesDir/relay/), using those."
				identity_file2="$configdir/$realIdentitiesDir/relay/$identity_file"
				group_file2="$configdir/$realIdentitiesDir/relay/$group_file"
			else
				echo -e "$warningMsg Trying to use real identities, but does not exists for relay (in $configdir/$realIdentitiesDir/relay/). Falling back to pre-generated ones."
			fi
		else
			echo -e "$warningMsg using pre-created identities. Set \"try_use_real_identities\" to True in real deployements."
		fi

		# test that all files exists
		test_files

		#run PriFi in relay mode
		DEBUG_COLOR="$colors" go run "$bin_file" --cothority_config "$identity_file2" --group "$group_file2" -d "$dbg_lvl" --prifi_config "$prifi_file2" --port "$socksServer1Port" --port_client "$socksServer2Port" relay
		;;

	trustee|Trustee|TRUSTEE)

		trusteeId="$2"

		#test for proper setup
		test_go
		test_cothority

		if [ "$#" -lt 2 ]; then
			echo -e "$errorMsg parameter 2 need to be the trustee id."
			exit 1
		fi
		test_digit "$trusteeId" 2

		#specialize the config file (we use the dummy folder, and maybe we replace with the real folder after)
		prifi_file2="$configdir/$prifi_file"
		identity_file2="$configdir/$defaultIdentitiesDir/trustee$trusteeId/$identity_file"
		group_file2="$configdir/$defaultIdentitiesDir/trustee$trusteeId/$group_file"

		#we we want to, try to replace with the real folder
		if [ "$try_use_real_identities" = "true" ]; then
			if [ -f "$configdir/$realIdentitiesDir/trustee$trusteeId/$identity_file" ] && [ -f "$configdir/$defaultIdentitiesDir/trustee$trusteeId/$group_file" ]; then
				echo -e "$okMsg Found real identities (in $configdir/$realIdentitiesDir/trustee$trusteeId/), using those."
				identity_file2="$configdir/$realIdentitiesDir/trustee$trusteeId/$identity_file"
				group_file2="$configdir/$realIdentitiesDir/trustee$trusteeId/$group_file"
			else
				echo -e "$warningMsg Trying to use real identities, but does not exists for trustee $trusteeId (in $configdir/$realIdentitiesDir/trustee$trusteeId/). Falling back to pre-generated ones."
			fi
		else
			echo -e "$warningMsg using pre-created identities. Set \"try_use_real_identities\" to True in real deployements."
		fi

		# test that all files exists
		test_files

		#run PriFi in relay mode
		DEBUG_COLOR="$colors" go run "$bin_file" --cothority_config "$identity_file2" --group "$group_file2" -d "$dbg_lvl" --prifi_config "$prifi_file2" --port "$socksServer1Port" --port_client "$socksServer2Port" trustee
		;;

	client|Client|CLIENT)

		clientId="$2"

		#test for proper setup
		test_go
		test_cothority

		if [ "$#" -lt 2 ]; then
			echo -e "$errorMsg parameter 2 need to be the client id."
			exit 1
		fi
		test_digit "$clientId" 2

		# the 3rd argument can replace the port number
		if [ "$#" -eq 3 ]; then
			test_digit "$3" 3
			socksServer1Port="$3"
		fi

		#specialize the config file (we use the dummy folder, and maybe we replace with the real folder after)
		prifi_file2="$configdir/$prifi_file"
		identity_file2="$configdir/$defaultIdentitiesDir/client$clientId/$identity_file"
		group_file2="$configdir/$defaultIdentitiesDir/client$clientId/$group_file"

		#we we want to, try to replace with the real folder
		if [ "$try_use_real_identities" = "true" ]; then
			if [ -f "$configdir/$realIdentitiesDir/client$clientId/$identity_file" ] && [ -f "$configdir/$realIdentitiesDir/client$clientId/$group_file" ]; then
				echo -e "$okMsg Found real identities (in $configdir/$realIdentitiesDir/client$clientId/), using those."
				identity_file2="$configdir/$realIdentitiesDir/client$clientId/$identity_file"
				group_file2="$configdir/$realIdentitiesDir/client$clientId/$group_file"
			else
				echo -e "$warningMsg Trying to use real identities, but does not exists for client $clientId (in $configdir/$realIdentitiesDir/client$clientId/). Falling back to pre-generated ones."
			fi
		else
			echo -e "$warningMsg using pre-created identities. Set \"try_use_real_identities\" to True in real deployements."
		fi

		# test that all files exists
		test_files

		#run PriFi in relay mode
		DEBUG_COLOR="$colors" go run "$bin_file" --cothority_config "$identity_file2" --group "$group_file2" -d "$dbg_lvl" --prifi_config "$prifi_file2" --port "$socksServer1Port" --port_client "$socksServer2Port" client
		;;

	sockstest|Sockstest|SOCKSTEST)

		#test for proper setup
		test_go
		test_cothority

		# the 2rd argument can replace the port number
		if [ "$#" -gt 1 ]; then
			test_digit "$2" 2
			socksServer1Port="$2"
		fi

		# the 3rd argument can replace the port_client number
		if [ "$#" -eq 3 ]; then
			test_digit "$3" 3
			socksServer2Port="$3"
		fi

		#specialize the config file, and test all files
		prifi_file2="$configdir/$prifi_file"
		identity_file2="$configdir/$defaultIdentitiesDir/relay/$identity_file"
		group_file2="$configdir/$defaultIdentitiesDir/relay/$group_file"
		test_files

		#run PriFi in relay mode
		DEBUG_COLOR="$colors" go run "$bin_file" --cothority_config "$identity_file2" --group "$group_file2" -d "$dbg_lvl" --prifi_config "$prifi_file2" --port "$socksServer1Port" --port_client "$socksServer2Port" sockstest
		;;

	localhost|Localhost|LOCALHOST|all-localhost|All-Localhost|ALL-LOCALHOST)

		thisScript="$0"
		if [ "$try_use_real_identities" = "true" ]; then
			echo -en "$warningMsg, try_use_real_identities set to true, but this is incompatible to all-localhost mode. Switching to false ..."
			sed -i -e 's/try_use_real_identities=\"true\"/try_use_real_identities=\"false\"/g' "$thisScript"
			echo -e "$okMsg"
		fi

		#test for proper setup
		test_go
		test_cothority

		#test if a socks proxy is already running (needed for relay), or start ours
		socks=$(netstat -tunpl 2>/dev/null | grep "$socksServer2Port" | wc -l)

		if [ "$socks" -ne 1 ]; then
			echo -n "Socks proxy not running, starting it... "
			cd socks && ./run-socks-proxy.sh "$socksServer2Port" > ../socks.log 2>&1 &
			SOCKSPID=$!
			echo -e "$okMsg"
		fi

		echo -n "Starting relay...			"
		"$thisScript" relay > relay.log 2>&1 &
		RELAYPID=$!
		THISPGID=$(ps -o pgid= "$RELAYPID" | sed -e "s/^ //")
		echo -e "$okMsg"

		sleep "$sleeptime_between_spawns"

		echo -n "Starting trustee 0...			"
		"$thisScript" trustee 0 > trustee0.log 2>&1 &
		echo -e "$okMsg"

		sleep "$sleeptime_between_spawns"

		for i in `seq 0 $(($all_localhost_n_clients - 1))`
		do
			port=$(($socksServer1Port + $i))
			log="client$i.log"
			echo -n "Starting client $i... (SOCKS on :$port)	"
			"$thisScript" client "$i" "$port" > "$log" 2>&1 &
			echo -e "$okMsg"
			sleep "$sleeptime_between_spawns"

		done

		read -p "PriFi deployed. Press [enter] to kill all..." key
		echo "Gonna run kill -TERM -- -\"$THISPGID\""

		kill -TERM -- -"$THISPGID"
		;;

	gen-id|Gen-Id|GEN-ID)
		echo -e "Going to generate private/public keys (named ${highlightOn}identity.toml${highlightOff})..."

		read -p "Do you want to generate it for [r]elay, [c]lient, or [t]trustee ? " key

		path=""
		case "$key" in
			r|R)
				path="relay"
			;;
			t|T)

				read -p "Do you want to generate it for trustee [0] or [1] (or more - enter digit) ? " key2

				test_digit "$key2" 1
				pathSource="trustee0"
				path="trustee$key2"
				;;

			c|C)
				read -p "Do you want to generate it for client [0],[1] or [2] (or more - enter digit) ? " key2

				test_digit "$key2" 1
				pathSource="client0"
				path="client$key2"
				;;


			*)
				echo -e "$errorMsg did not understand."
				exit 1
				;;
		esac

		pathReal="$configdir/$realIdentitiesDir/$path/"
		pathDefault="$configdir/$defaultIdentitiesDir/$pathSource/"
		echo -e "Gonna generate ${highlightOn}identity.toml${highlightOff} in ${highlightOn}$pathReal${highlightOff}"

		#generate identity.toml
		DEBUG_COLOR="$colors" go run "$bin_file" --default_path "$pathReal" gen-id

		#now group.toml
		echo -n "Done ! now copying group.toml from identities_default/ to identity_real/..."
		cp "${pathDefault}/group.toml" "${pathReal}group.toml"
		echo -e "$okMsg"

		echo -e "Please edit ${highlightOn}$pathReal/group.toml${highlightOff} to the correct values."
		;;

	integration-test)

		pkill prifi 2>/dev/null
		kill -TERM $(pidof "go run run-server.go") 2>/dev/null

		thisScript="$0"
		"$thisScript" clean

		rm -f relay.log 2>/dev/null # just to be sure...

		echo -n "Starting relay...			"
		"$thisScript" relay > relay.log 2>&1 &
		echo -e "$okMsg"

		sleep "$sleeptime_between_spawns"

		echo -n "Starting trustee 0...			"
		"$thisScript" trustee 0 > trustee0.log 2>&1 &
		echo -e "$okMsg"

		sleep "$sleeptime_between_spawns"

		echo -n "Starting client 0... (SOCKS on :8081)	"
		"$thisScript" client 0 8081 > client0.log 2>&1 &
		echo -e "$okMsg"

		if [ "$all_localhost_n_clients" -gt 1 ]; then
			sleep "$sleeptime_between_spawns"

			echo -n "Starting client 1... (SOCKS on :8082)	"
			"$thisScript" client 1 8082 > client1.log 2>&1 &
			echo -e "$okMsg"
		fi

		if [ "$all_localhost_n_clients" -gt 2 ]; then
			sleep "$sleeptime_between_spawns"

			echo -n "Starting client 2... (SOCKS on :8083)	"
			"$thisScript" client 2 8083 > client2.log 2>&1 &
			echo -e "$okMsg"
		fi

		#let it boot
		waitTime=10
		echo "Waiting $waitTime seconds..."
		sleep "$waitTime"

		#reporting is every 5 second by default. if we wait 30, we should have 6 of those
		lines=$(cat relay.log | grep -E "([0-9\.]+) round/sec, ([0-9\.]+) kB/s up, ([0-9\.]+) kB/s down, ([0-9\.]+) kB/s down\(udp\)" | wc -l)

		echo "Number of reportings : $lines"

		pkill prifi 2>/dev/null
		kill -TERM $(pidof "go run run-server.go")  2>/dev/null

		if [ "$lines" -gt 1 ]; then
			echo "Test succeeded"
			exit 0
		else
			echo "Test failed"
			exit 1
		fi
		;;

	integration-test2)

		pkill prifi 2>/dev/null
		kill -TERM $(pidof "go run run-server.go") 2>/dev/null

		thisScript="$0"
		"$thisScript" clean

		rm -f relay.log 2>/dev/null # just to be sure...

		#test if a socks proxy is already running (needed for relay), or start ours
		socks=$(netstat -tunpl 2>/dev/null | grep "$socksServer2Port" | wc -l)

		if [ "$socks" -ne 1 ]; then
			echo -n "Socks proxy not running, starting it... "
			cd socks && ./run-socks-proxy.sh "$socksServer2Port" > ../socks.log 2>&1 &
			SOCKSPID=$!
			echo -e "$okMsg"
		fi

		echo -n "Starting relay...			"
		"$thisScript" relay > relay.log 2>&1 &
		echo -e "$okMsg"

		sleep "$sleeptime_between_spawns"

		echo -n "Starting trustee 0...			"
		"$thisScript" trustee 0 > trustee0.log 2>&1 &
		echo -e "$okMsg"

		sleep "$sleeptime_between_spawns"

		echo -n "Starting client 0... (SOCKS on :8081)	"
		"$thisScript" client 0 8081 > client0.log 2>&1 &
		echo -e "$okMsg"

		if [ "$all_localhost_n_clients" -gt 1 ]; then
			sleep "$sleeptime_between_spawns"

			echo -n "Starting client 1... (SOCKS on :8082)	"
			"$thisScript" client 1 8082 > client1.log 2>&1 &
			echo -e "$okMsg"
		fi

		if [ "$all_localhost_n_clients" -gt 2 ]; then
			sleep "$sleeptime_between_spawns"

			echo -n "Starting client 2... (SOCKS on :8083)	"
			"$thisScript" client 2 8083 > client2.log 2>&1 &
			echo -e "$okMsg"
		fi

		#let it boot
		sleep 20

		echo "Doing SOCKS HTTP request..."
		curl google.com --socks5 127.0.0.1:8081 --max-time 10 1>/dev/null 2>&1
		res=$?

		pkill prifi 2>/dev/null
		kill -TERM $(pidof "go run run-server.go")  2>/dev/null

		if [ "$res" -eq 0 ]; then
			echo "Test succeeded"
			exit 0
		else
			echo "Test failed"
			exit 1
		fi
		;;

	relay-d)

		#test for proper setup
		test_go
		test_cothority

		thisScript="$0"

		echo -n "Starting relay...			"
		"$thisScript" relay > relay.log 2>&1 &
		RELAYPID=$!
		RELAYPGID=$(ps -o pgid= "$RELAYPID")
		echo -e "$okMsg"

		echo -e "PriFi relay deployed, PGID $RELAYPGID. Kill with \"kill -TERM -- -$RELAYPID\""
		;;

	trustee-d)

		#test for proper setup
		test_go
		test_cothority

		thisScript="$0"
		trusteeId="$2"

		if [ "$#" -lt 2 ]; then
			echo -e "$errorMsg parameter 2 need to be the client id."
			exit 1
		fi
		test_digit "$trusteeId" 2

		echo -n "Starting trustee $trusteeId...			"
		"$thisScript" trustee "$trusteeId" > trustee${trusteeId}.log 2>&1 &
		TRUSTEEPID=$!
		TRUSTEEGPID=$(ps -o pgid= "$TRUSTEEPID")
		echo -e "$okMsg"

		echo -e "PriFi trustee deployed, PGID $TRUSTEEGPID. Kill with \"kill -TERM -- -$TRUSTEEGPID\""
		;;

	socks-d)

		echo -n "Starting SOCKS Server...			"
		cd socks && ./run-socks-proxy.sh "$socksServer2Port" > ../socks.log 2>&1 &
		SOCKSPID=$!
		SOCKSPGID=$(ps -o pgid= "$SOCKSPID")
		echo -e "$okMsg"

		echo -e "PriFi trustee deployed, PGID $SOCKSPGID. Kill with \"kill -TERM -- -$SOCKSPGID\""
		;;

	simul|Simul|SIMUL)


		#create a file ~/pings.sh with this content
		#  #!/bin/sh
		#  for ip in 10.0.1.1 10.1.0.1; do
		#      echo "Pinging $ip"
		#      ssh relay.LB-LLD.SAFER.isi.deterlab.net "ping $ip -w 10 -c 10 | grep rtt"
		#	   echo -n ";"
		#  done
		# [EOF]

		EXPERIMENT_ID_VALUE=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
		SIMUL_FILE="prifi_simul.toml"
		PLATFORM="deterlab"
		EXEC_NAME="prifi_simul"
		SIMUL_DIR="sda/simulation"
		deterlabUser="lbarman"
		MPORT="10002"
		dbg_lvl=1

		rm -f last-simul.log

		echo -n "Building simulation... " | tee last-simul.log
		cd "$SIMUL_DIR"; go build -o "$EXEC_NAME" *.go | tee ../../last-simul.log
		echo -e "$okMsg" | tee ../../last-simul.log

		echo -en "Simulation ID is ${highlightOn}${EXPERIMENT_ID_VALUE}${highlightOff}, storing it in ${highlightOn}~/remote/.simID${highlightOff} on remote... " | tee ../../last-simul.log
		ssh $deterlabUser@users.deterlab.net "echo ${EXPERIMENT_ID_VALUE} > ~/remote/.simID"  | tee ../../last-simul.log
		ssh $deterlabUser@users.deterlab.net "rm -f ~/remote/.lastsimul"
		echo -e "$okMsg" | tee ../../last-simul.log

		echo -e "Starting simulation ${highlightOn}${SIMUL_FILE}${highlightOff} on ${highlightOn}${PLATFORM}${highlightOff}." | tee ../../last-simul.log
		DEBUG_LVL=$dbg_lvl DEBUG_COLOR=$colors ./"$EXEC_NAME" -platform "$PLATFORM" -mport "$MPORT" "$SIMUL_FILE" | tee ../../last-simul.log

		echo -n "Simulation done, cleaning up... " | tee ../../last-simul.log
		rm -f "$EXEC_NAME" | tee ../../last-simul.log
		echo -e "$okMsg" | tee ../../last-simul.log
		
		status=$(ssh $deterlabUser@users.deterlab.net "cat ~/remote/.lastsimul")
		echo -e "Status is ${highlightOn}${status}${highlightOff}." | tee ../../last-simul.log

		;;

	simul-p|simul-ping)

		deterlabUser="lbarman"

		echo -n "Mesuring latencies... "
		pings=$(ssh $deterlabUser@users.deterlab.net "./pings.sh")
		echo -e "$okMsg"
		echo $pings | sed -e "s/10.0.1.1/client0/" | sed -e "s/10.1.0.1/trustee0/" | tr ';' '\n'
		;;

	simul-gl|simul-get-logs)

		#create a file ~/makelogsrw.sh with this content
		#	#!/bin/sh
		#	ssh relay.LB-LLD.SAFER.isi.deterlab.net 'cd remote; sudo chmod ugo+rw -R .'
		# [EOF]

		expFolder="experiment_out"
		deterlabUser="lbarman"

		echo -e "${warningMsg} Note that this tool downloads every log on the server. If you forgot to clean them, it might concern serveral experiments."

		echo -n "Making logs R/W... " #this is needed since simul runs and writes log as root
		ssh $deterlabUser@users.deterlab.net './makelogsrw.sh'
		echo -e "$okMsg"

		read -p "Which name do you want to give the data on the server ? " expName

		if [ -d "$expFolder/$expName" ]; then
			echo -e "${errorMsg} Directory ${highlightOn}$expFolder/$expName${highlightOff} already exists, exiting."
			exit 1
		fi

		echo -ne "Making folder ${highlightOn}$expFolder/$expName${highlightOff} "
		mkdir -p "$expFolder/$expName"
		echo -e "$okMsg"

		echo -ne "Fetching all experiments of the form ${highlightOn}output_*${highlightOff} "
		cd "$expFolder/$expName";
		out=$(scp -r $deterlabUser@users.deterlab.net:~/remote/output_\* . )
		echo -e "$okMsg"

		echo -ne "Writing the download date... "
		date > "download_date"
		echo -e "$okMsg"

		echo -ne "Changing rights back to something normal... ${highlightOn}u+rwx,go-rwx${highlightOff} "
		chmod u+rwx -R .
		chmod go-rwx -R .
		echo -e "$okMsg"

		echo "Copied files are :"
		echo ""
		cd ..
		tree -a "$expName"

		;;

	simul-cl|simul-clear-logs)

		#create a file ~/makelogsrw.sh with this content
		#	#!/bin/sh
		#	ssh relay.LB-LLD.SAFER.isi.deterlab.net 'cd remote; sudo chmod ugo+rw -R .'
		# [EOF]

		deterlabUser="lbarman"

		echo -e "${warningMsg} This tool *deletes* all experiment data on the remote server. Make sure you backuped what you need !"

		read -p "Would you like to continue and *delete* all logs [y/n] ? " ans

		if [ $ans = y -o $ans = Y -o $ans = yes -o $ans = Yes -o $ans = YES ]
		then

			echo -n "Making logs R/W... " #this is needed since simul runs and writes log as root
			ssh $deterlabUser@users.deterlab.net './makelogsrw.sh'
			echo -e "$okMsg"

			echo -n "Deleting all remote logs... "
			ssh $deterlabUser@users.deterlab.net 'cd remote; rm -rf output_*;'
			echo -e "$okMsg"

		else
			echo "Aborting without taking any action."
		fi

		;;

	simul-vary-nclients)

		thisScript="$0"

		NTRUSTEES=1
		NRELAY=1
		TEMPLATE_FILE="sda/simulation/prifi_simul_template.toml"
		CONFIG_FILE="sda/simulation/prifi_simul.toml"
		TIMEOUT="300"

		"$thisScript" simul-cl

		for repeat in {4..6}
		do
			for i in {10..90..10}
			do
				hosts=$(($NTRUSTEES + $NRELAY + $i))
				echo "Simulating for HOSTS=$hosts..."

				#fix the config
				rm -f "$CONFIG_FILE"
				sed "s/Hosts = x/Hosts = $hosts/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

				timeout "$TIMEOUT" "$thisScript" simul | tee experiment_${i}_${repeat}.txt
			done
		done

		;;

	simul-vary-nclients2)

		thisScript="$0"

		NTRUSTEES=1
		NRELAY=1
		TEMPLATE_FILE="sda/simulation/prifi_simul_template.toml"
		CONFIG_FILE="sda/simulation/prifi_simul.toml"
		TIMEOUT="600"

		for i in {10..90..10}
		do
			for repeat in {1..4}
			do
				hosts=$(($NTRUSTEES + $NRELAY + $i))
				echo "Simulating for HOSTS=$hosts..."

				#fix the config
				rm -f "$CONFIG_FILE"
				sed "s/Hosts = x/Hosts = $hosts/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

				timeout "$TIMEOUT" "$thisScript" simul | tee experiment_${i}_${repeat}.txt
			done
		done

		;;

	simul-vary-sleep)

		thisScript="$0"

		NTRUSTEES=3
		NRELAY=1
		TEMPLATE_FILE="sda/simulation/prifi_simul_template.toml"
		CONFIG_FILE="sda/simulation/prifi_simul.toml"
		TIMEOUT="400"

		"$thisScript" simul-cl

		for repeat in {1..10}
		do
			for i in {0..100..10}
			do
				echo "Simulating for Delay=$i..."

				#fix the config
				rm -f "$CONFIG_FILE"
				sed "s/OpenClosedSlotsMinDelayBetweenRequests = x/OpenClosedSlotsMinDelayBetweenRequests = $i/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

				timeout "$TIMEOUT" "$thisScript" simul | tee experiment_${i}_${repeat}.txt
			done
		done

		;;

	simul-mcast-rules|simul-mr)

		#create a file ~/mcast2.sh with this content
		# #!/bin/sh
		# iface=$(ip addr | sed -r ':a;N;$!ba;s/\n\s/ /g' | sed -r -n -e 's/^([0-9]+):\s(\w+).*(link\/(\w+))\s[a-f0-9:.]{,17}\sbrd\s[a-f0-9:.]{,17}\s*(inet\s([0-9]{1,3}(\.[0-9]{1,3}){3})).*/\2 \6 \4/p' -e 's/^([0-9]+):\s(\w+).*(link\/(\w+))\s[a-f0-9:.]{,17}\sbrd\s[a-f0-9:.]{,17}.*/\2 0.0.0.0 \4/p' | grep 10.0.1 | cut -d ' ' -f 1)
		# echo "Redirecting mcast traffic to $iface"
		# sudo route del -net 224.0.0.0/8
		# sudo route add -net 224.0.0.0/8 "$iface"
		# [EOF]

		#create a file ~/mcast.sh with this content
		# #!/bin/sh
		# echo "Connecting to relay"
		# ssh relay.LB-LLD.SAFER.isi.deterlab.net './mcast2.sh'
		# for i in 0 1 2 3 4; do
		#     echo "Connecting to client-$i"
		#     ssh client-$i.LB-LLD.SAFER.isi.deterlab.net './mcast2.sh'
		# done
		# [EOF]
		
		deterlabUser="lbarman"

		echo -n "Setting multicast to go through 10.0.1.0/8 network... "
		ssh $deterlabUser@users.deterlab.net './mcast.sh'
		echo -e "$okMsg"
		;;

	simul-vary-window)

		thisScript="$0"

		TEMPLATE_FILE="sda/simulation/prifi_simul_template.toml"
		CONFIG_FILE="sda/simulation/prifi_simul.toml"
		TIMEOUT="400"

		"$thisScript" simul-cl

		for repeat in {1..3}
		do
			for window in {1..10}
			do
				echo "Simulating for WINDOW=$window..."

				#fix the config
				rm -f "$CONFIG_FILE"
				sed "s/RelayWindowSize = x/RelayWindowSize = $window/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

				timeout "$TIMEOUT" "$thisScript" simul | tee experiment_${window}_${repeat}.txt
			done
		done
		;;

	simul-vary-upstream)

		thisScript="$0"

		TEMPLATE_FILE="sda/simulation/prifi_simul_template.toml"
		CONFIG_FILE="sda/simulation/prifi_simul.toml"
		TIMEOUT="400"

		"$thisScript" simul-cl

		for repeat in {1..10}
		do
			for upsize in 1000 2000 3000 4000 5000 6000 7000 8000 9000 10000
			do
				echo "Simulating for upsize=$upsize  (repeat $repeat)..."

				#fix the config
				rm -f "$CONFIG_FILE"
				sed "s/CellSizeUp = x/CellSizeUp = $upsize/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

				timeout "$TIMEOUT" "$thisScript" simul | tee experiment_${upsize}_${repeat}.txt
			done
		done
		;;

	simul-vary-downstream)

		thisScript="$0"

		TEMPLATE_FILE="sda/simulation/prifi_simul_template.toml"
		CONFIG_FILE="sda/simulation/prifi_simul.toml"
		TIMEOUT="400"

		"$thisScript" simul-cl

		for repeat in {1..10}
		do
			for downsize in 17400 17500 17600 17800 17900 18000
			do
				echo "Simulating for downsize=$downsize  (repeat $repeat)..."

				#fix the config
				rm -f "$CONFIG_FILE"
				sed "s/CellSizeDown = x/CellSizeDown = $downsize/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

				timeout "$TIMEOUT" "$thisScript" simul | tee experiment_${downsize}_${repeat}.txt
			done
		done
		;;

	simul-e|simul-edit)

		nano sda/simulation/prifi_simul.toml
		;;


	clean|Clean|CLEAN)
		echo -n "Cleaning local log files... 			"
		rm *.log 1>/dev/null 2>&1
		echo -e "$okMsg"
		;;


	ping-through-prifi)

		#create a file ~/curl_format.cnf with this content
		#
		#    time_namelookup:  %{time_namelookup}\n
		#       time_connect:  %{time_connect}\n
		#    time_appconnect:  %{time_appconnect}\n
		#   time_pretransfer:  %{time_pretransfer}\n
		#      time_redirect:  %{time_redirect}\n
		# time_starttransfer:  %{time_starttransfer}\n
		#                    ----------\n
		#         time_total:  %{time_total}\n

		echo -n "Performing CURL through SOCKS:8081 to google.com, measuring latency..."

		for repeat in {1..10}
		do
			#curl -w "@curl_format.cnf" --socks5 127.0.0.1:8081 --max-time 10 -o /dev/null -s "http://google.com/"
			curl -w "@curl_format.cnf" --socks5 127.0.0.1:8081 --max-time 10 -o /dev/null -s "http://google.com/" > curl_ping_$repeat.txt
		done

		echo -e "$okMsg"
		;;

	*)
		print_usage
		;;
esac
