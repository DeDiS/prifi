package prifi_socks

import (
  "net"
  "fmt"
  "bufio"
  "io"
  "encoding/binary"
  "errors"
  "strconv"
)

// Authentication methods
const (
  methNoAuth = iota
  methGSS
  methUserPass
  methNone = 0xff
)

// Address types
const (
  addrIPv4   = 0x01
  addrDomain = 0x03
  addrIPv6   = 0x04
)

// Commands
const (
  cmdConnect   = 0x01
  cmdBind      = 0x02
  cmdAssociate = 0x03
)

// Reply codes
const (
  repSucceeded = iota
  repGeneralFailure
  repConnectionNotAllowed
  repNetworkUnreachable
  repHostUnreachable
  repConnectionRefused
  repTTLExpired
  repCommandNotSupported
  repAddressTypeNotSupported
)


func HandleClient(conn net.Conn) {
    
    allChannels := make( map[uint32]chan []byte )

    fmt.Println("Handling Conection")

    /*   Client SOCKS Request Handling     */

    connReader := bufio.NewReader(conn)

    for {

    connID, _, _, clientPacket, err :=  readFull(connReader)
    if err != nil {
      //handle error
      fmt.Println("Data Read Error")
      return
    }


    if connID == 0 { //We don't care about these packets
      continue
    }

    myChan := allChannels[connID]

    if myChan == nil {

      newChan := make(chan []byte)
      allChannels[connID] = newChan

      go hanndleChannel(conn, newChan, connID)

      myChan = newChan

    } 

    myChan <- clientPacket
}
    
}



func hanndleChannel(conn net.Conn, clientPacket chan []byte, connID uint32) {
  
  connReader := newChanReader(clientPacket)

  //Read SOCKS Version
    socksVersion := []byte{0}
    _, err := io.ReadFull(connReader,socksVersion)
    if err != nil {
      //handle error
      fmt.Println("Version Error")
      return
    } else if int(socksVersion[0]) != 5 {
      //handle socks version
      fmt.Println("Version:", int( socksVersion[0] ) )
      return
    }


    //Read SOCKS Number of Methods
    socksNumOfMethods := []byte{0}
    _ , err = io.ReadFull(connReader,socksNumOfMethods)
    if err != nil {
      //handle error

      return
    }


    //Read SOCKS Methods
    numOfMethods := int( socksNumOfMethods[0] )
    socksMethods := make([]byte, numOfMethods)
    _, err = io.ReadFull(connReader,socksMethods)
    if err != nil {
      //handle error

      return
    }


    // Find a supported method (currently only NoAuth)
    foundMethod := false
    for i := 0; i< len(socksMethods); i++ {
      if socksMethods[i] == methNoAuth {
        foundMethod = true
        break
      }
    }

    if !foundMethod {
      //handle not finding method

      return
    }



    //Construct Response Message
    methodSelectionResponse := []byte{ socksVersion[0] , byte(methNoAuth) }
    sendMessage(conn, NewDataWrap(connID,uint16(len(methodSelectionResponse)),uint16(len(methodSelectionResponse))+dataWrapHeaderSize,methodSelectionResponse))




    /*   Client Web Request Handling    */

    requestHeader := make([] byte, 4)
    _, err = io.ReadFull(connReader,requestHeader)
    if err != nil {
      //handle error
      fmt.Println("Request Header Error")
      return
    }

    destinationIP, err :=  readSocksAddr(connReader, int(requestHeader[3]))
    if err != nil {
      //handle error
      fmt.Println("IP Address Error")
      return
    }


    destinationPortBytes := make([]byte, 2)
    _, err = io.ReadFull(connReader,destinationPortBytes)
    if err != nil {
      //handle error
      fmt.Println("Destination Port Error")
      return
    }
    destinationPort := binary.BigEndian.Uint16(destinationPortBytes)


    destinationAddress := (&net.TCPAddr{IP: destinationIP, Port: int(destinationPort)}).String()
    //destinationAddress := fmt.Sprintf("%s:%d", destinationIP, destinationPort)

    fmt.Println("Connecting to Web Server @",destinationAddress)

    // Process the command
    switch int(requestHeader[1]) {
      case cmdConnect:
        webConn, err := net.Dial("tcp", destinationAddress)
        if err != nil {
          fmt.Println("Failed to connect to web server")
          return
        }

        // Send success reply downstream
        sucessMessage := createSocksReply(0, conn.LocalAddr())
        sendMessage(conn, NewDataWrap(connID,uint16(len(sucessMessage)),uint16(len(sucessMessage))+dataWrapHeaderSize,sucessMessage))

        // Commence forwarding raw data on the connection
        go proxyClientPackets(webConn, conn, connID)
        go proxyWebServerPackets(webConn, connReader, connID)

      default:
        fmt.Println("Cannot Process Command")
    }

}




func proxyClientPackets(webConn net.Conn, conn net.Conn, connID uint32) {
  for {
    buf := make([]byte, 100000)
    n, _ := webConn.Read(buf)
    buf = buf[:n]
    // Forward the data (or close indication if n==0) downstream
    sendMessage(conn, NewDataWrap(connID,uint16(n),uint16(n)+dataWrapHeaderSize,buf))

    // Connection error or EOF?
    if n == 0 {
      fmt.Println("Disconnected from Web Server")
      webConn.Close()
      return
    }
  }
}


func proxyWebServerPackets(webConn net.Conn, connReader io.Reader, connID uint32) {

  for {
    // Get the next upstream data buffer
    buf := make([]byte, 100000)
    messageLength, err := connReader.Read(buf)
    if err != nil {
      //handle error
      fmt.Println("Header Error")
      return
    }

    if messageLength == 0 { // connection close indicator
      return
    }
    //println(hex.Dump(buf))
    n, err := webConn.Write(buf[:messageLength])
    if n != messageLength {
      return
    }

  }
}








// Read an IPv4 or IPv6 address from an io.Reader and return it as a string
func readIP(r io.Reader, len int) (net.IP, error) {
  errorIP := make(net.IP, net.IPv4len)

  addr := make([]byte, len)
  _, err := io.ReadFull(r, addr)
  if err != nil {
    return errorIP, err
  }
  return net.IP(addr), nil
}

func readSocksAddr(cr io.Reader, addrtype int) (net.IP, error) {
  
 errorIP := make(net.IP, net.IPv4len)

  switch addrtype {
  case addrIPv4:
    return readIP(cr, net.IPv4len)

  case addrIPv6:
    return readIP(cr, net.IPv6len)

  case addrDomain:

    // First read the 1-byte domain name length
    dlen := [1]byte{}
    _, err := io.ReadFull(cr, dlen[:])
    if err != nil {
      return errorIP, err
    }

    // Now the domain name itself
    domain := make([]byte, int(dlen[0]))
    _, err = io.ReadFull(cr, domain)
    if err != nil {
      return errorIP, err
    }

    return net.IP(domain), nil

  default:
    msg := fmt.Sprintf("unknown SOCKS address type %d", addrtype)
    fmt.Println(msg)
    return errorIP, errors.New(msg)
  }

}


func createSocksReply(replyCode int, addr net.Addr) []byte {
  
  buf := make([]byte, 4)
  buf[0] = byte(5) // version
  buf[1] = byte(replyCode)

   // Address type
  if addr != nil {

    tcpaddr := addr.(*net.TCPAddr)
    host4 := tcpaddr.IP.To4()
    host6 := tcpaddr.IP.To16()

    i, _ := strconv.Atoi("6789")

    port := [2]byte{}
    binary.BigEndian.PutUint16(port[:], uint16(i))//tcpaddr.Port))

    if host4 != nil { // it's an IPv4 address

      buf[3] = addrIPv4
      buf = append(buf, host4...)
      buf = append(buf, port[:]...)

    } else if host6 != nil { // it's an IPv6 address

      buf[3] = addrIPv6
      buf = append(buf, host6...)
      buf = append(buf, port[:]...)

    } else { // huh???

      fmt.Println("SOCKS: neither IPv4 nor IPv6 addr?")
      addr = nil
      buf[1] = byte(repAddressTypeNotSupported)

    }

  } else { // attach a null IPv4 address
    buf[3] = addrIPv4
    buf = append(buf, make([]byte, 4+2)...)
  }

   return buf
 }







