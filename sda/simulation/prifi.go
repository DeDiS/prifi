package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/BurntSushi/toml"
	prifi_protocol "github.com/lbarman/prifi/sda/protocols"
	prifi_service "github.com/lbarman/prifi/sda/services"
	"github.com/lbarman/prifi/utils/output"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FILE_SIMULATION_ID is the file where the simulation ID is stored
const FILE_SIMULATION_ID = ".simID"

/*
 * Defines the simulation for the service-template
 */

func init() {
	onet.SimulationRegister("PriFi", NewSimulationService)
}

// SimulationService only holds the BFTree simulation
type SimulationService struct {
	SimulationManualAssignment
	prifi_protocol.PrifiTomlConfig
	NTrustees             int
	TrusteeIPRegexPattern string
	ClientIPRegexPattern  string
	RelayIPRegexPattern   string
}

// NewSimulationService returns the new simulation, where all fields are
// initialised using the config-file
func NewSimulationService(config string) (onet.Simulation, error) {
	es := &SimulationService{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (s *SimulationService) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}

	return sc, nil
}

// identifyNodeType is used when simulating on deterlab. The IP address is
// matched against 3 regex, and the match tells the node type
func (s *SimulationService) identifyNodeType(config *onet.SimulationConfig, nodeID network.ServerIdentityID) string {

	_, v := config.Roster.Search(nodeID)

	relayRegex := regexp.MustCompile(s.RelayIPRegexPattern)
	clientRegex := regexp.MustCompile(s.ClientIPRegexPattern)
	trusteeRegex := regexp.MustCompile(s.TrusteeIPRegexPattern)

	addrStr := v.Address.String()

	if relayRegex.MatchString(addrStr) {
		return "relay"
	} else if clientRegex.MatchString(addrStr) {
		return "client"
	} else if trusteeRegex.MatchString(addrStr) {
		return "trustee"
	}
	log.Fatal("Unrecognized node type, IP is", addrStr)
	return "" // never happens
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *SimulationService) Node(config *onet.SimulationConfig) error {

	// identify who we are given our IP (works only on deterlab !)
	i, v := config.Roster.Search(config.Server.ServerIdentity.ID)
	whoami := s.identifyNodeType(config, config.Server.ServerIdentity.ID)
	log.Lvl1("Node #"+strconv.Itoa(i)+" running on server", v.Address, "and will be a", whoami)

	// this is (should be) used in localhost instead of whoami above, AND on deterlab for having
	// different ports numbers when multiples hosts are on one server
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	if err := s.SimulationManualAssignment.Node(config); err != nil {
		log.Fatal("Could not register node in SDA Tree", err)
	}

	s.SocksServerPort = 8080 + index

	//assign the roles
	roles := make(map[*network.ServerIdentity]string)
	for _, v := range config.Roster.List {
		roles[v] = s.identifyNodeType(config, v.ID)
	}
	group := &app.Group{Roster: config.Roster, Description: roles}

	//finds the PriFi service
	service := config.GetService(prifi_service.ServiceName).(*prifi_service.ServiceState)

	//override log level, maybe
	if s.OverrideLogLevel > 0 {
		log.Lvl1("Overriding log level (from .toml) to", s.OverrideLogLevel)
		log.SetDebugVisible(s.OverrideLogLevel)
	}
	if s.ForceConsoleColor {
		log.Lvl1("Forcing the console output to be colored (from .toml)")
		log.SetUseColors(true)
	}

	//set the config from the .toml file
	service.SetConfigFromToml(&s.PrifiTomlConfig)

	//start this node in the correct setup
	var err error
	if index == 0 {
		log.Lvl1("Initiating this node (index ", index, ") as relay")
		err = service.StartRelay(group)
	} else if index > 0 && index <= s.NTrustees {
		log.Lvl1("Initiating this node (index ", index, ") as trustee")
		err = service.StartTrustee(group)
	} else {
		log.Lvl1("Initiating this node (index ", index, ") as client")
		err = service.StartClient(group)
	}

	if err != nil {
		log.Fatal("Error instantiating this node, ", err)
	}

	return nil
}

// Run is used on the destination machines and runs a number of
// rounds
func (s *SimulationService) Run(config *onet.SimulationConfig) error {

	//this is run only on the relay. Get the simulation ID stored by the shell script
	simulationIDBytes, err := ioutil.ReadFile(FILE_SIMULATION_ID)
	if err != nil {
		log.Fatal("Could not read file", FILE_SIMULATION_ID, "error is", err)
	}
	simulationID := string(simulationIDBytes)

	//finds the PriFi service
	service := config.GetService(prifi_service.ServiceName).(*prifi_service.ServiceState)

	for round := 0; round < s.Rounds; round++ {

		log.Info("Sleeping 10 seconds before next round...")
		time.Sleep(10 * time.Second)

		log.Info("Starting experiment", simulationID, "round", round)

		for !service.HasEnoughParticipants() {
			t, c := service.CountParticipants()
			log.Info("Not enough participants (", t, "trustees,", c, "clients), sleeping 10 seconds...")
			time.Sleep(10 * time.Second)
		}

		service.StartPriFiCommunicateProtocol()

		//the art of programming : waiting for an event (not even thread safe!)
		for service.PriFiSDAProtocol == nil {
			time.Sleep(10 * time.Millisecond)
		}
		for service.PriFiSDAProtocol.ResultChannel == nil {
			time.Sleep(10 * time.Millisecond)
		}

		//block and get the result from the channel
		res := <-service.PriFiSDAProtocol.ResultChannel
		resStringArray := res.([]string)

		//create folder for this experiment
		folderName := "output_" + simulationID + "/" + hashString(config.Config)
		if _, err := os.Stat(folderName); err != nil {
			os.MkdirAll(folderName, 0777)

			//write config
			filePath := path.Join(folderName, "config")
			err = ioutil.WriteFile(filePath, []byte(fmt.Sprintf("%+v", config)), 0777)
			if err != nil {
				log.Error("Could not write config into file", filePath)
			}
		}

		//write to file
		o := new(output.FileOutput)
		filePath := path.Join(folderName, "output_r"+strconv.Itoa(round)+".txt")
		o.Filename = filePath
		log.Info("Simulation results stored in", o.Filename)
		for _, s := range resStringArray {
			o.Print(s)
		}

		service.StopPriFiCommunicateProtocol()
	}
	service.GlobalShutDownSocks()

	//stop the SOCKS stuff (will be restarted next round)

	return nil
}
func hashString(data string) string {
	hasher := sha1.New() //this is not a crypto hash, and 256 is too long to be human-readable
	hasher.Write([]byte(data))
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	//just for readability
	sha = strings.Replace(sha, "=", "", -1)
	sha = strings.Replace(sha, "-", "", -1)
	sha = strings.Replace(sha, "_", "", -1)
	sha = strings.Replace(sha, "/", "", -1)

	return sha
}
