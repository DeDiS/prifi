#!/usr/bin/env bash


# ************************************
# PriFi all-in-one startup script
# ************************************
# author : Ludovic Barman
# email : ludovic.barman@gmail.com
# belongs to : the PriFi project<github.com/lbarman/prifi>
# ************************************

# variables that you might change often

dbg_lvl=3                                  # 1=less verbose, 3=more verbose. goes up to 5, but then prints the SDA's message (network framework)
colors="true"                              # if  "false", the output of PriFi (and this script) will be in black-n-white

# Experiment settings

SIMUL_FILE="prifi_simul.toml"
PLATFORM="deterlab"
EXEC_NAME="prifi_simul"
SIMUL_DIR="sda/simulation"
DETERLAB_USER="lbarman"
MPORT="10002"

TEMPLATE_FILE="sda/simulation/prifi_simul_template.toml"
CONFIG_FILE="sda/simulation/prifi_simul.toml"

SIMULATION_TIMEOUT="400"                   # note: in simul-vary-xxx, this is the timeout of *one* tick, no the whole loop

# default file names :

MAIN_SCRIPT="./prifi.sh"
THIS_SCRIPT="$0"

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
    echo -e "** This is the simulation interface that interacts with Deterlab **. For advanced use only."
    echo
    echo -e "Usage: simul.sh ${highlightOn}role/operation [params]${highlightOff}. Please check the .sh file for operations."
    echo 
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

# ------------------------
#     MAIN SWITCH
# ------------------------

# $1 is operation : "simul", "simul-ping", "simul-get-logs", "simul-clear-logs", "simul-vary-nclients", "simul-vary-nclients2", "simul-mcast-rules", etc
case $1 in

    simul|Simul|SIMUL)



        EXPERIMENT_ID_VALUE=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
        dbg_lvl=1 # do not change this. Many other functions of this script call this script recursively. If this is >1, the log will blow up ;)

        rm -f last-simul.log

        echo -n "Building simulation... " | tee last-simul.log
        cd "$SIMUL_DIR"; go build -o "$EXEC_NAME" *.go | tee ../../last-simul.log
        echo -e "$okMsg" | tee ../../last-simul.log

        echo -en "Simulation ID is ${highlightOn}${EXPERIMENT_ID_VALUE}${highlightOff}, storing it in ${highlightOn}~/remote/.simID${highlightOff} on remote... " | tee ../../last-simul.log
        ssh $DETERLAB_USER@users.deterlab.net "echo ${EXPERIMENT_ID_VALUE} > ~/remote/.simID"  | tee ../../last-simul.log
        ssh $DETERLAB_USER@users.deterlab.net "rm -f ~/remote/.lastsimul"
        echo -e "$okMsg" | tee ../../last-simul.log

        echo -e "Starting simulation ${highlightOn}${SIMUL_FILE}${highlightOff} on ${highlightOn}${PLATFORM}${highlightOff}." | tee ../../last-simul.log
        DEBUG_LVL=$dbg_lvl DEBUG_COLOR=$colors ./"$EXEC_NAME" -platform "$PLATFORM" -mport "$MPORT" "$SIMUL_FILE" | tee ../../last-simul.log

        echo -n "Simulation done, cleaning up... " | tee ../../last-simul.log
        rm -f "$EXEC_NAME" | tee ../../last-simul.log
        echo -e "$okMsg" | tee ../../last-simul.log
        
        status=$(ssh $DETERLAB_USER@users.deterlab.net "cat ~/remote/.lastsimul")
        echo -e "Status is ${highlightOn}${status}${highlightOff}." | tee ../../last-simul.log

        ;;

    simul-p|simul-ping)

        #create a file ~/pings.sh with this content
        #  #!/bin/sh
        #  for ip in 10.0.1.1 10.1.0.1; do
        #      echo "Pinging $ip"
        #      ssh relay.LB-LLD.SAFER.isi.deterlab.net "ping $ip -w 10 -c 10 | grep rtt"
        #      echo -n ";"
        #  done
        # [EOF]

        echo -n "Mesuring latencies... "
        pings=$(ssh $DETERLAB_USER@users.deterlab.net "./pings.sh")
        echo -e "$okMsg"
        echo $pings | sed -e "s/10.0.1.1/client0/" | sed -e "s/10.1.0.1/trustee0/" | tr ';' '\n'
        ;;

    simul-gl|simul-get-logs)

        #create a file ~/makelogsrw.sh with this content
        #   #!/bin/sh
        #   ssh relay.LB-LLD.SAFER.isi.deterlab.net 'cd remote; sudo chmod ugo+rw -R .'
        # [EOF]

        expFolder="experiment_out"

        echo -e "${warningMsg} Note that this tool downloads every log on the server. If you forgot to clean them, it might concern serveral experiments."

        echo -n "Making logs R/W... " #this is needed since simul runs and writes log as root
        ssh $DETERLAB_USER@users.deterlab.net './makelogsrw.sh'
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
        out=$(scp -r $DETERLAB_USER@users.deterlab.net:~/remote/output_\* . )
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
        #   #!/bin/sh
        #   ssh relay.LB-LLD.SAFER.isi.deterlab.net 'cd remote; sudo chmod ugo+rw -R .'
        # [EOF]

        echo -e "${warningMsg} This tool *deletes* all experiment data on the remote server. Make sure you backuped what you need !"

        read -p "Would you like to continue and *delete* all logs [y/n] ? " ans

        if [ $ans = y -o $ans = Y -o $ans = yes -o $ans = Yes -o $ans = YES ]
        then

            echo -n "Making logs R/W... " #this is needed since simul runs and writes log as root
            ssh $DETERLAB_USER@users.deterlab.net './makelogsrw.sh'
            echo -e "$okMsg"

            echo -n "Deleting all remote logs... "
            ssh $DETERLAB_USER@users.deterlab.net 'cd remote; rm -rf output_*;'
            echo -e "$okMsg"

        else
            echo "Aborting without taking any action."
        fi

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
        
        echo -n "Setting multicast to go through 10.0.1.0/8 network... "
        ssh $DETERLAB_USER@users.deterlab.net './mcast.sh'
        echo -e "$okMsg"
        ;;

    simul-vary-nclients)

        NTRUSTEES=3
        NRELAY=1

        "$THIS_SCRIPT" simul-cl

        for repeat in {1..4}
        do
            for i in {10..90..10}
            do
                hosts=$(($NTRUSTEES + $NRELAY + $i))
                echo "Simulating for HOSTS=$hosts..."

                #fix the config
                rm -f "$CONFIG_FILE"
                sed "s/Hosts = x/Hosts = $hosts/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

                timeout "$SIMULATION_TIMEOUT" "$THIS_SCRIPT" simul | tee experiment_${i}_${repeat}.txt
            done
        done

        ;;

    simul-vary-sleep)

        NTRUSTEES=3
        NRELAY=1

        "$THIS_SCRIPT" simul-cl

        for repeat in {1..10}
        do
            for i in {0..100..10}
            do
                echo "Simulating for Delay=$i..."

                #fix the config
                rm -f "$CONFIG_FILE"
                sed "s/OpenClosedSlotsMinDelayBetweenRequests = x/OpenClosedSlotsMinDelayBetweenRequests = $i/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

                timeout "$SIMULATION_TIMEOUT" "$THIS_SCRIPT" simul | tee experiment_${i}_${repeat}.txt
            done
        done

        ;;

    simul-vary-window)

        "$THIS_SCRIPT" simul-cl

        for repeat in {1..3}
        do
            for window in {1..10}
            do
                echo "Simulating for WINDOW=$window..."

                #fix the config
                rm -f "$CONFIG_FILE"
                sed "s/RelayWindowSize = x/RelayWindowSize = $window/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

                timeout "$SIMULATION_TIMEOUT" "$THIS_SCRIPT" simul | tee experiment_${window}_${repeat}.txt
            done
        done
        ;;

    simul-vary-upstream)

        "$THIS_SCRIPT" simul-cl

        for repeat in {1..10}
        do
            for upsize in 1000 2000 3000 4000 5000 6000 7000 8000 9000 10000
            do
                echo "Simulating for upsize=$upsize  (repeat $repeat)..."

                #fix the config
                rm -f "$CONFIG_FILE"
                sed "s/CellSizeUp = x/CellSizeUp = $upsize/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

                timeout "$SIMULATION_TIMEOUT" "$THIS_SCRIPT" simul | tee experiment_${upsize}_${repeat}.txt
            done
        done
        ;;

    simul-vary-downstream)

        "$THIS_SCRIPT" simul-cl

        for repeat in {1..10}
        do
            for downsize in 17400 17500 17600 17800 17900 18000
            do
                echo "Simulating for downsize=$downsize  (repeat $repeat)..."

                #fix the config
                rm -f "$CONFIG_FILE"
                sed "s/CellSizeDown = x/CellSizeDown = $downsize/g" "$TEMPLATE_FILE" > "$CONFIG_FILE"

                timeout "$SIMULATION_TIMEOUT" "$THIS_SCRIPT" simul | tee experiment_${downsize}_${repeat}.txt
            done
        done
        ;;

    simul-e|simul-edit)

        nano sda/simulation/prifi_simul.toml
        ;;

    *)
        test_go
        test_cothority
        print_usage
        ;;
esac
