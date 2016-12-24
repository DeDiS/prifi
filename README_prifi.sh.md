# PriFi: A Low-Latency, Tracking-Resistant Protocol for Local-Area Anonymity [![Build Status](https://travis-ci.org/lbarman/prifi.svg?branch=master)](https://travis-ci.org/lbarman/prifi)

[back to main README](README.md)

## More details on ./prifi.sh

## Running PriFi

### SOCKS Preamble

As explained, you need a non-prifi SOCKS server running to handle the traffic from the relay. If you don't have one, run ours :
```
./socks/run-socks-proxy.sh 8090
```
(you don't need to do this if you run `./prifi.sh all-localhost`, it done for you)

## Running PriFi

There is one big startup script `prifi.sh`. 

```
./prifi.sh 
Usage: run-prifi.sh role/operation [params]
	role: client, relay, trustee
	operation: sockstest, all, deploy-all
	params for role relay: [socks_server_port] (optional, numeric)
	params for role trustee: id (required, numeric)
	params for role client: id (required, numeric), [prifi_socks_server_port] (optional, numeric)
	params for operation all, deploy: none
	params for operation sockstest, deploy: [socks_server_port] (optional, numeric), [prifi_socks_server_port] (optional, numeric)

```

For instance, you can start a relay like this : 

```
./prifi.sh relay 8090
```

You can start a client like this :

```
./prifi.sh client 0
```

and to specify the port of the first socks proxy integrated in PriFi :

```
./prifi.sh client 0 8080
```

A typical deployement could be :

```
./prifi.sh relay 8090
./prifi.sh trustee 0
./prifi.sh client 0 8080
./prifi.sh client 1 8081
```

## Configuration

The PriFi configuration file is in `config.demo/prifi.toml`

- `DataOutputEnbaled (bool)`: Enables the link from and to the socks proxy.
- `NTrustees (int)`: Number of trustees.
- `CellSizeUp (int)`: Size of upstream data sent in one PriFi round (?)
- `CellSizeDown (int)`: Size of upstream data sent in one PriFi round (?)
- `RelayWindowSize (int)`: Number of ciphers from each trustee to buffer
- `RelayUseDummyDataDown (bool)`: When true, the relay always send
CellSizeDown bits down. When false, it may send only 1 bit.
- `RelayReportingLimit (int)`: Unused, was for the statistics.
- `UseUDP (bool)`: Enable or disable UDP broadcast for downstream data (?)
- `DoLatencyTests (bool)`: Enable or disable latency tests.
- `ReportingLimit (int)`: PriFi shuts down after this number of rounds if
not equal to `-1`.