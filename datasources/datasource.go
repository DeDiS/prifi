package datasources

type DataSource interface {

	//returns true IFF source has data to send
	HasData() bool

	//argument: currentRoundID, payloadLength [byte]
	//returns a []byte with data
	GetDataFromSource(int, int) ([]byte)

	//Confirms to the source that roundID was indeed sent
	AckDataToSource(int)

	//argument: currentRoundID, data
	//sends data back to the source
	SendDataToSource(int32, []byte)
}