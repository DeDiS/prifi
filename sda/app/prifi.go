/*
Prifi-app starts a cothority node in either trustee, relay or client mode.
*/
package main

import (
	"fmt"
	"os"

	"io/ioutil"
	"os/user"
	"path"
	"runtime"

	"bytes"
	"github.com/BurntSushi/toml"
	prifi_protocol "github.com/lbarman/prifi/sda/protocols"
	prifi_service "github.com/lbarman/prifi/sda/services"
	"gopkg.in/dedis/crypto.v0/abstract"
	cryptoconfig "gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/app"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/urfave/cli.v1"
	"net"
	"os/exec"
	"strconv"
	"time"
)

// DefaultName is the name of the binary we produce and is used to create a directory
// folder with this name
const DefaultName = "prifi"

// Default name of configuration file
const DefaultCothorityConfigFile = "identity.toml"

// Default name of group file
const DefaultCothorityGroupConfigFile = "group.toml"

// Default name of prifi's config file
const DefaultPriFiConfigFile = "prifi.toml"

// DefaultPort to listen and connect to. As of this writing, this port is not listed in
// /etc/services
const DefaultPort = 6879

// This app can launch the prifi service in either client, trustee or relay mode
func main() {
	app := cli.NewApp()
	app.Name = "prifi"
	app.Usage = "Starts PriFi in either Trustee, Relay or Client mode."
	app.Version = "0.1"
	app.Commands = []cli.Command{
		{
			Name:    "gen-id",
			Aliases: []string{"gen"},
			Usage:   "creates a new identity.toml",
			Action:  createNewIdentityToml,
		},
		{
			Name:    "trustee",
			Usage:   "start in trustee mode",
			Aliases: []string{"t"},
			Action:  startTrustee,
		},
		{
			Name:      "relay",
			Usage:     "start in relay mode",
			ArgsUsage: "group [id-name]",
			Aliases:   []string{"r"},
			Action:    startRelay,
		},
		{
			Name:    "client",
			Usage:   "start in client mode",
			Aliases: []string{"c"},
			Action:  startClient,
		},
		{
			Name:    "sockstest",
			Usage:   "only starts the socks server and the socks clients without prifi",
			Aliases: []string{"socks"},
			Action:  startSocksTunnelOnly,
		},
	}
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
		cli.StringFlag{
			Name:  "cothority_config, cc",
			Value: getDefaultFilePathForName(DefaultCothorityConfigFile),
			Usage: "configuration-file",
		},
		cli.StringFlag{
			Name:  "prifi_config, pc",
			Value: getDefaultFilePathForName(DefaultPriFiConfigFile),
			Usage: "configuration-file",
		},
		cli.IntFlag{
			Name:  "port, p",
			Value: 12345,
			Usage: "port for the socks server (this is the port that you need to set in your browser)",
		},
		cli.IntFlag{
			Name:  "port_client",
			Value: 8081,
			Usage: "port for the socks client (that will connect to a remote socks server)",
		},
		cli.StringFlag{
			Name:  "group, g",
			Value: getDefaultFilePathForName(DefaultCothorityGroupConfigFile),
			Usage: "Group file",
		},
		cli.StringFlag{
			Name:  "default_path",
			Value: ".",
			Usage: "The default creation path for identity.toml when doing gen-id",
		},
		cli.BoolFlag{
			Name:  "nowait",
			Usage: "Return immediately",
		},
	}
	app.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}
	app.Run(os.Args)
}

/**
 * Every "app" require reading config files and starting cothority beforehand
 */
func readConfigAndStartCothority(c *cli.Context) (*onet.Server, *app.Group, *prifi_service.ServiceState) {
	//parse PriFi parameters
	prifiTomlConfig, err := readPriFiConfigFile(c)

	//override log level and color
	if prifiTomlConfig.OverrideLogLevel > 0 {
		log.Lvl3("Overriding log level (from .toml) to", prifiTomlConfig.OverrideLogLevel)
		log.SetDebugVisible(prifiTomlConfig.OverrideLogLevel)
	}
	if prifiTomlConfig.ForceConsoleColor {
		log.Lvl3("Forcing the console output to be colored (from .toml)")
		log.SetUseColors(true)
	}

	if err != nil {
		log.Error("Could not read prifi config:", err)
		os.Exit(1)
	}

	//start cothority server
	host, err := startCothorityNode(c)
	if err != nil {
		log.Error("Could not start Cothority server:", err)
		os.Exit(1)
	}

	//finds the PriFi service
	service := host.GetService(prifi_service.ServiceName).(*prifi_service.ServiceState)

	//set the config from the .toml file
	service.SetConfigFromToml(prifiTomlConfig)

	//reads the group description
	group := readCothorityGroupConfig(c)
	if err != nil {
		log.Error("Could not read the group description:", err)
		os.Exit(1)
	}

	prifiTomlConfig.ProtocolVersion = getGitCommitID()

	return host, group, service
}

// This folder's git commit ID is used as a Protocol Version field to avoid mismatched version between nodes
func getGitCommitID() string {
	var (
		cmdOut []byte
		err    error
	)

	cmdName := "git"
	cmdArgs := []string{"rev-parse", "HEAD"}

	//sends the command to the shell and retrieves the commitID for HEAD
	if cmdOut, err = exec.Command(cmdName, cmdArgs...).Output(); err != nil {
		log.Error("There was an error running git rev-parse command: ", err)
		os.Exit(1)
	}

	return string(cmdOut)
}

// trustee start the cothority in trustee-mode using the already stored configuration.
func startTrustee(c *cli.Context) error {
	log.Info("Starting trustee")

	host, group, service := readConfigAndStartCothority(c)

	if err := service.StartTrustee(group); err != nil {
		log.Error("Could not start the prifi service:", err)
		os.Exit(1)
	}

	host.Router.AddErrorHandler(service.NetworkErrorHappened)
	host.Start()
	return nil
}

// relay starts the cothority in relay-mode using the already stored configuration.
func startRelay(c *cli.Context) error {
	log.Info("Starting relay")

	host, group, service := readConfigAndStartCothority(c)

	service.AutoStart = true
	if err := service.StartRelay(group); err != nil {
		log.Error("Could not start the prifi service:", err)
		os.Exit(1)
	}

	host.Router.AddErrorHandler(service.NetworkErrorHappened)
	host.Start()
	return nil
}

// client starts the cothority in client-mode using the already stored configuration.
func startClient(c *cli.Context) error {
	log.Info("Starting client")

	host, group, service := readConfigAndStartCothority(c)

	if err := service.StartClient(group, time.Duration(0)); err != nil {
		log.Error("Could not start the prifi service:", err)
		os.Exit(1)
	}

	host.Router.AddErrorHandler(service.NetworkErrorHappened)
	host.Start()
	return nil
}

// this is used to test the socks server and clients integrated to PriFi, without using DC-nets.
func startSocksTunnelOnly(c *cli.Context) error {
	log.Info("Starting socks tunnel (bypassing PriFi)")

	host, _, service := readConfigAndStartCothority(c)

	if err := service.StartSocksTunnelOnly(); err != nil {
		log.Error("Could not start the prifi service:", err)
		os.Exit(1)
	}

	host.Start()
	return nil
}

/**
 * COTHORITY
 */

// Returns true if file exists and user confirms overwriting, or if file doesn't exist.
// Returns false if file exists and user doesn't confirm overwriting.
func checkOverwrite(file string) bool {
	// check if the file exists and ask for override
	if _, err := os.Stat(file); err == nil {
		return app.InputYN(true, "Configuration file "+file+" already exists. Override?")
	}
	return true
}

func createNewIdentityToml(c *cli.Context) error {

	log.Print("Generating public/private keys...")

	privStr, pubStr := createKeyPair()

	addrPort := app.Inputf(":"+strconv.Itoa(DefaultPort)+"", "Which port do you want PriFi to use locally ?")

	//parse IP + Port
	var hostStr string
	var portStr string

	host, port, err := net.SplitHostPort(addrPort)
	log.ErrFatal(err, "Couldn't interpret", addrPort)

	if addrPort == "" {
		portStr = strconv.Itoa(DefaultPort)
		hostStr = "127.0.0.1"
	} else if host == "" {
		hostStr = "127.0.0.1"
		portStr = port
	} else {
		hostStr = host
		portStr = port
	}

	serverBinding := network.NewTCPAddress(hostStr + ":" + portStr)

	identity := &app.CothorityConfig{
		Public:  pubStr,
		Private: privStr,
		Address: serverBinding,
	}

	var configDone bool
	var folderPath string
	var identityFilePath string

	for !configDone {
		// get name of config file and write to config file
		defaultPath := "."

		if c.GlobalIsSet("default_path") {
			defaultPath = c.GlobalString("default_path")
		}

		folderPath = app.Inputf(defaultPath, "Please enter the path for the new identity.toml file:")
		identityFilePath = path.Join(folderPath, DefaultCothorityConfigFile)

		// check if the directory exists
		if _, err := os.Stat(folderPath); os.IsNotExist(err) {
			log.Info("Creating inexistant directories for ", folderPath)
			if err = os.MkdirAll(folderPath, 0744); err != nil {
				log.Fatalf("Could not create directory %s %v", folderPath, err)
			}
		}

		if checkOverwrite(identityFilePath) {
			break
		}
	}

	if err := identity.Save(identityFilePath); err != nil {
		log.Fatal("Unable to write the config to file:", err)
	}

	//now since cothority is smart enough to write only the decimal format of the key, AND require the base64 format for group.toml, let's add it as a comment

	public, err := crypto.StringHexToPub(network.Suite, pubStr)
	if err != nil {
		log.Fatal("Impossible to parse public key:", err)
	}
	var buff bytes.Buffer
	if err := crypto.Write64Pub(network.Suite, &buff, public); err != nil {
		log.Error("Can't convert public key to base 64")
		return nil
	}

	f, err := os.OpenFile(identityFilePath, os.O_RDWR|os.O_APPEND, 0660)

	if err != nil {
		log.Fatal("Unable to write the config to file (2):", err)
	}
	publicKeyBase64String := string(buff.Bytes())
	f.WriteString("# Public (base64) = " + publicKeyBase64String + "\n")
	f.Close()

	log.Info("Identity file saved.")

	return nil
}

// Starts the cothority node to enable communication with the prifi-service.
func startCothorityNode(c *cli.Context) (*onet.Server, error) {
	// first check the options
	cfile := c.GlobalString("cothority_config")

	if _, err := os.Stat(cfile); os.IsNotExist(err) {
		log.Error("Could not open file \"", cfile, "\" (specified by flag cothority_config)")
		return nil, err
	}
	// Let's read the config
	_, host, err := app.ParseCothority(cfile)
	if err != nil {
		log.Error("Could not parse file", cfile)
		return nil, err
	}
	return host, nil
}

/**
 * CONFIG
 */

func readPriFiConfigFile(c *cli.Context) (*prifi_protocol.PrifiTomlConfig, error) {

	cfile := c.GlobalString("prifi_config")

	if _, err := os.Stat(cfile); os.IsNotExist(err) {
		log.Error("Could not open file \"", cfile, "\" (specified by flag prifi_config)")
		return nil, err
	}

	tomlRawData, err := ioutil.ReadFile(cfile)
	if err != nil {
		log.Error("Could not read file \"", cfile, "\" (specified by flag prifi_config)")
	}

	tomlConfig := &prifi_protocol.PrifiTomlConfig{}

	_, err = toml.Decode(string(tomlRawData), tomlConfig)
	if err != nil {
		log.Error("Could not parse toml file", cfile)
		return nil, err
	}

	//ports can be overridden by the command line params
	if c.GlobalIsSet("port") {
		tomlConfig.SocksServerPort = c.GlobalInt("port")
	}
	if c.GlobalIsSet("port_client") {
		tomlConfig.SocksClientPort = c.GlobalInt("port_client")
	}

	return tomlConfig, nil
}

// getDefaultFile creates a path to the default config folder and appends fileName to it.
func getDefaultFilePathForName(fileName string) string {
	u, err := user.Current()
	// can't get the user dir, so fallback to current working dir
	if err != nil {
		fmt.Print("[-] Could not get your home's directory. Switching back to current dir.")
		if curr, err := os.Getwd(); err != nil {
			log.Fatalf("Impossible to get the current directory. %v", err)
		} else {
			return path.Join(curr, fileName)
		}
	}
	// let's try to stick to usual OS folders
	switch runtime.GOOS {
	case "darwin":
		return path.Join(u.HomeDir, "Library", DefaultName, fileName)
	default:
		return path.Join(u.HomeDir, ".config", DefaultName, fileName)
		// TODO WIndows ? FreeBSD ?
	}
}

// getGroup reads the group-file and returns it.
func readCothorityGroupConfig(c *cli.Context) *app.Group {

	gfile := c.GlobalString("group")

	if _, err := os.Stat(gfile); os.IsNotExist(err) {
		log.Error("Could not open file \"", gfile, "\" (specified by flag group)")
		return nil
	}

	gr, err := os.Open(gfile)

	if err != nil {
		log.Error("Could not read file \"", gfile, "\"")
		return nil
	}

	defer gr.Close()

	groups, err := app.ReadGroupDescToml(gr)

	if err != nil {
		log.Error("Could not parse toml file \"", gfile, "\"")
		return nil
	}

	if groups == nil || groups.Roster == nil || len(groups.Roster.List) == 0 {
		log.Error("No servers found in roster from", gfile)
		return nil
	}
	return groups
}

// createKeyPair returns the private and public key in hexadecimal representation.
func createKeyPair() (string, string) {
	kp := cryptoconfig.NewKeyPair(network.Suite)
	privStr, err := crypto.ScalarToStringHex(network.Suite, kp.Secret)
	if err != nil {
		log.Fatal("Error formating private key to hexadecimal. Abort.")
	}
	var point abstract.Point
	// use the transformation for EdDSA signatures
	//point = cosi.Ed25519Public(network.Suite, kp.Secret)
	point = kp.Public
	pubStr, err := crypto.PubToStringHex(network.Suite, point)
	if err != nil {
		log.Fatal("Could not parse public key. Abort.")
	}

	return privStr, pubStr
}
