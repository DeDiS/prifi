package net

import (
	"github.com/dedis/protobuf"
	"testing"
)

func TestUtils(t *testing.T) {

	m := new(ALL_ALL_PARAMETERS_NEW)

	m.Add("key1", "val1")
	m.Add("key2", 123)
	m.Add("key3", true)

	if m.ParamsStr["key1"] != "val1" {
		t.Error("key1 should equals val1")
	}
	if m.ParamsInt["key2"] != 123 {
		t.Error("key2 should equals 123")
	}
	if m.ParamsBool["key3"] != true {
		t.Error("key3 should equals true")
	}

	if m.StringValueOrElse("key1", "else") != "val1" {
		t.Error("key1 should equals val1")
	}
	if m.IntValueOrElse("key2", 324) != 123 {
		t.Error("key2 should equals 123")
	}
	if m.BoolValueOrElse("key3", false) != true {
		t.Error("key3 should equals true")
	}

	if m.StringValueOrElse("key5", "else") != "else" {
		t.Error("non-existent key should return elseVal")
	}
	if m.IntValueOrElse("key6", 324) != 324 {
		t.Error("non-existent key should return elseVal")
	}
	if m.BoolValueOrElse("key7", false) != false {
		t.Error("non-existent key should return elseVal")
	}
}

func TestEncodeDecodeStdMessage(t *testing.T) {

	//create fake message
	msg := &REL_CLI_DOWNSTREAM_DATA{RoundID: 1, Data: make([]byte, 0), FlagResync: true, HashRoundID: -1, Hash: make([]byte, 0)}

	//encode it
	bytes, err := protobuf.Encode(msg)

	if err != nil {
		t.Error("Could not encode, " + err.Error())
	}

	_ = bytes

	//decode it
	emptyMsg := &REL_CLI_DOWNSTREAM_DATA{}
	err = protobuf.Decode(bytes, emptyMsg)
	if err != nil {
		t.Error("Could not decode," + err.Error())
	}

	if emptyMsg.RoundID != msg.RoundID {
		t.Error("RoundID should be the same")
	}
	if emptyMsg.HashRoundID != msg.HashRoundID {
		t.Error("RoundID should be the same")
	}
	if emptyMsg.FlagResync != msg.FlagResync {
		t.Error("FlagResync should be the same")
	}
}

func TestEncodeDecode(t *testing.T) {

	//create fake message
	msg := new(ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true
	msg.Add("key1", "val1")
	msg.Add("key2", 123)
	msg.Add("key3", true)

	//encode it
	bytes, err := protobuf.Encode(msg)

	if err != nil {
		t.Error("Could not encode," + err.Error())
	}

	//decode it
	emptyMsg := &ALL_ALL_PARAMETERS_NEW{}
	err = protobuf.Decode(bytes, emptyMsg)
	if err != nil {
		t.Error("Could not decode," + err.Error())
	}

	if emptyMsg.ForceParams != true {
		t.Error("ForceParams should be true")
	}
	if emptyMsg.StringValueOrElse("key1", "otherVal") != "val1" {
		t.Error("key1 should be val1")
	}
	if emptyMsg.IntValueOrElse("key2", 999) != 123 {
		t.Error("key2 should be 123")
	}
	if emptyMsg.BoolValueOrElse("key3", false) != true {
		t.Error("key3 should be true")
	}
}

func TestEncodeDecodeEmpty(t *testing.T) {

	//create fake message
	msg := new(ALL_ALL_PARAMETERS_NEW)
	msg.ForceParams = true

	//encode it
	bytes, err := protobuf.Encode(msg)

	if err != nil {
		t.Error("Could not encode, " + err.Error())
	}

	//decode it
	emptyMsg := new(ALL_ALL_PARAMETERS_NEW)
	err = protobuf.Decode(bytes, emptyMsg)
	if err != nil {
		t.Error("Could not decode," + err.Error())
	}

	if emptyMsg.ForceParams != true {
		t.Error("ForceParams should be true")
	}
	if emptyMsg.StringValueOrElse("key1", "otherVal") != "otherVal" {
		t.Error("key1 should be otherVal")
	}
}
