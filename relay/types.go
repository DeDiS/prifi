package relay

import (
	"github.com/dedis/crypto/abstract"
	"github.com/lbarman/prifi/dcnet"
	prifinet "github.com/lbarman/prifi/net"
	"net"
	"time"
)

const MaxUint uint32 = uint32(4294967295)

const CONTROL_LOOP_SLEEP_TIME = 1 * time.Second
const PROCESSING_LOOP_SLEEP_TIME = 0 * time.Second
const INBETWEEN_CONFIG_SLEEP_TIME = 0 * time.Second
const NEWCLIENT_CHECK_SLEEP_TIME = 10 * time.Millisecond
const CLIENT_READ_TIMEOUT = 5 * time.Second
const FAILED_CONNECTION_WAIT_BEFORE_RETRY = 10 * time.Second

const (
	PROTOCOL_STATUS_OK = iota
	PROTOCOL_STATUS_GONNA_RESYNC
	PROTOCOL_STATUS_RESYNCING
)

type IdConnectionAndPublicKey struct {
	Id        int
	Conn      net.Conn
	PublicKey abstract.Point
}

type RelayState struct {
	Name               string
	RelayPort          string

	PublicKey          abstract.Point
	privateKey         abstract.Scalar

	nClients           int
	nTrustees          int
	PublicKeyRoster    map[int]abstract.Point

	UseUDP             bool
	UseDummyDataDown   bool
	UDPBroadcastConn   net.Conn

	trusteesHosts      []string

	clients            []prifinet.NodeRepresentation
	trustees           []prifinet.NodeRepresentation

	CellCoder          dcnet.CellCoder

	DownstreamHistory  abstract.Cipher

	UpstreamCellSize   int
	DownstreamCellSize int
	WindowSize         int
	ReportingLimit     int

	AuthMethod         int
}
