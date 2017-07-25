package client

type DataSource interface {
	HasData() bool

	GetDataFromSource() (int, []byte)

	AckDataToSource(int)

	SendDataToSource([]byte)
}
