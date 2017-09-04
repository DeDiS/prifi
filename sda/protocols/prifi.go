package protocols

import (
	prifi_lib "github.com/lbarman/prifi/prifi-lib"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

//PriFiRole is the type of the enum to qualify the role of a SDA node (Relay, Client, Trustee)
type PriFiRole int

//The possible states of a SDA node, of type PriFiRole
const (
	Relay PriFiRole = iota
	Client
	Trustee
)

//PriFiIdentity is the identity (role + ID)
type PriFiIdentity struct {
	Role     PriFiRole
	ID       int
	ServerID *network.ServerIdentity
}

//SOCKSConfig contains the port, payload, and up/down channels for data
type SOCKSConfig struct {
	Port              string
	PayloadLength     int
	UpstreamChannel   chan []byte
	DownstreamChannel chan []byte
}

//The configuration read in prifi.toml
type PrifiTomlConfig struct {
	ForceConsoleColor                      bool
	OverrideLogLevel                       int
	ClientDataOutputEnabled                bool
	RelayDataOutputEnabled                 bool
	CellSizeUp                             int
	CellSizeDown                           int
	RelayWindowSize                        int
	RelayUseOpenClosedSlots                bool
	RelayUseDummyDataDown                  bool
	RelayReportingLimit                    int
	UseUDP                                 bool
	DoLatencyTests                         bool
	SocksServerPort                        int
	SocksClientPort                        int
	ProtocolVersion                        string
	DCNetType                              string
	ReplayPCAP                             bool
	PCAPFolder                             string
	TrusteeNeverSlowDown                   bool
	SimulDelayBetweenClients               int
	DisruptionProtectionEnabled            bool
	EquivocationProtectionEnabled          bool // not linked in the back
	OpenClosedSlotsMinDelayBetweenRequests int
}

//PriFiSDAWrapperConfig is all the information the SDA-Protocols needs. It contains the network map of identities, our role, and the socks parameters if we are the corresponding role
type PriFiSDAWrapperConfig struct {
	Toml                  *PrifiTomlConfig
	Identities            map[string]PriFiIdentity
	Role                  PriFiRole
	ClientSideSocksConfig *SOCKSConfig
	RelaySideSocksConfig  *SOCKSConfig
	udpChan               UDPChannel
}

// SetConfig configures the PriFi node.
// It **MUST** be called in service.newProtocol or before Start().
func (p *PriFiSDAProtocol) SetConfigFromPriFiService(config *PriFiSDAWrapperConfig) {
	p.config = *config
	p.role = config.Role

	ms := p.buildMessageSender(config.Identities)
	p.ms = ms

	//sanity check
	switch config.Role {
	case Trustee:
		if ms.relay == nil {
			log.Fatal("Relay is not reachable (I'm a trustee, and I need it) !")
		}
	case Client:
		if ms.relay == nil {
			log.Fatal("Relay is not reachable (I'm a client, and I need it) !")
		}
	case Relay:
		if len(ms.clients) < 1 {
			log.Fatal("Less than one client reachable (I'm a relay, and there's no use starting the protocol) !")
		}
		if len(ms.trustees) < 1 {
			log.Fatal("No trustee reachable (I'm a relay, and I cannot start the protocol) !")
		}
	}

	experimentResultChan := p.ResultChannel

	switch config.Role {
	case Relay:
		relayOutputEnabled := config.Toml.RelayDataOutputEnabled
		p.prifiLibInstance = prifi_lib.NewPriFiRelay(relayOutputEnabled,
			config.RelaySideSocksConfig.DownstreamChannel, config.RelaySideSocksConfig.UpstreamChannel,
			experimentResultChan, config.Toml.OpenClosedSlotsMinDelayBetweenRequests, p.handleTimeout, ms)
	case Trustee:
		p.prifiLibInstance = prifi_lib.NewPriFiTrustee(config.Toml.TrusteeNeverSlowDown, ms)

	case Client:
		doLatencyTests := config.Toml.DoLatencyTests
		clientDataOutputEnabled := config.Toml.ClientDataOutputEnabled
		p.prifiLibInstance = prifi_lib.NewPriFiClient(doLatencyTests, clientDataOutputEnabled,
			config.ClientSideSocksConfig.UpstreamChannel, config.ClientSideSocksConfig.DownstreamChannel,
			config.Toml.ReplayPCAP, config.Toml.PCAPFolder, ms)
	}

	p.registerHandlers()

	p.configSet = true
}

// SetTimeoutHandler sets the function that will be called on round timeout
// if the protocol runs as the relay.
func (p *PriFiSDAProtocol) SetTimeoutHandler(handler func([]string, []string)) {
	p.toHandler = handler
}
