package datasources

import (
	"fmt"
	"time"
	"testing"
)


func TestTimeStamp(t *testing.T) {
	v := MsTimeStampNow() // we can't check this
	loc, _ := time.LoadLocation("UTC")
	specificDate := time.Date(2007, 06, 14, 01, 02, 03, 0, loc)
	fmt.Println(specificDate)
	v = MsTimeStamp(specificDate)
	if v != 1181782923000 {
		t.Error("Timestamp conversion failed")
	}
}