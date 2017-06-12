package protocols

//Received_ALL_ALL_SHUTDOWN shuts down the PriFi-lib if it is running
func (p *PriFiSDAProtocol) Received_ALL_ALL_SHUTDOWN(msg Struct_ALL_ALL_SHUTDOWN) error {
	p.Stop()
	err := p.prifiLibInstance.ReceivedMessage(msg.ALL_ALL_SHUTDOWN)
	return err
}

//Received_ALL_ALL_PARAMETERS forwards an ALL_ALL_PARAMETERS message to PriFi's lib
func (p *PriFiSDAProtocol) Received_ALL_ALL_PARAMETERS_NEW(msg Struct_ALL_ALL_PARAMETERS_NEW) error {
	return p.prifiLibInstance.ReceivedMessage(msg.ALL_ALL_PARAMETERS_NEW)
}

//Received_REL_CLI_DOWNSTREAM_DATA forwards an REL_CLI_DOWNSTREAM_DATA message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_CLI_DOWNSTREAM_DATA(msg Struct_REL_CLI_DOWNSTREAM_DATA) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_CLI_DOWNSTREAM_DATA)
}

//Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG forwards an REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG(msg Struct_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG)
}

//Received_REL_CLI_TELL_TRUSTEES_PK forwards an REL_CLI_TELL_TRUSTEES_PK message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_CLI_TELL_TRUSTEES_PK(msg Struct_REL_CLI_TELL_TRUSTEES_PK) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_CLI_TELL_TRUSTEES_PK)
}

//Received_CLI_REL_TELL_PK_AND_EPH_PK forwards an CLI_REL_TELL_PK_AND_EPH_PK message to PriFi's lib
func (p *PriFiSDAProtocol) Received_CLI_REL_TELL_PK_AND_EPH_PK(msg Struct_CLI_REL_TELL_PK_AND_EPH_PK) error {
	return p.prifiLibInstance.ReceivedMessage(msg.CLI_REL_TELL_PK_AND_EPH_PK)
}

//Received_CLI_REL_UPSTREAM_DATA forwards an CLI_REL_UPSTREAM_DATA message to PriFi's lib
func (p *PriFiSDAProtocol) Received_CLI_REL_UPSTREAM_DATA(msg Struct_CLI_REL_UPSTREAM_DATA) error {
	return p.prifiLibInstance.ReceivedMessage(msg.CLI_REL_UPSTREAM_DATA)
}

//Received_CLI_REL_UPSTREAM_DATA forwards an CLI_REL_UPSTREAM_DATA message to PriFi's lib
func (p *PriFiSDAProtocol) Received_CLI_REL_CLI_REL_OPENCLOSED_DATA(msg Struct_CLI_REL_OPENCLOSED_DATA) error {
	return p.prifiLibInstance.ReceivedMessage(msg.CLI_REL_OPENCLOSED_DATA)
}

//Received_TRU_REL_DC_CIPHER forwards an TRU_REL_DC_CIPHER message to PriFi's lib
func (p *PriFiSDAProtocol) Received_TRU_REL_DC_CIPHER(msg Struct_TRU_REL_DC_CIPHER) error {
	return p.prifiLibInstance.ReceivedMessage(msg.TRU_REL_DC_CIPHER)
}

//Received_TRU_REL_SHUFFLE_SIG forwards an TRU_REL_SHUFFLE_SIG message to PriFi's lib
func (p *PriFiSDAProtocol) Received_TRU_REL_SHUFFLE_SIG(msg Struct_TRU_REL_SHUFFLE_SIG) error {
	return p.prifiLibInstance.ReceivedMessage(msg.TRU_REL_SHUFFLE_SIG)
}

//Received_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS forwards an TRU_REL_TELL_NEW_BASE_AND_EPH_PKS message to PriFi's lib
func (p *PriFiSDAProtocol) Received_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS(msg Struct_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS) error {
	return p.prifiLibInstance.ReceivedMessage(msg.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS)
}

//Received_TRU_REL_TELL_PK forward an TRU_REL_TELL_PK message to PriFi's lib
func (p *PriFiSDAProtocol) Received_TRU_REL_TELL_PK(msg Struct_TRU_REL_TELL_PK) error {
	return p.prifiLibInstance.ReceivedMessage(msg.TRU_REL_TELL_PK)
}

//Received_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE forward an REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE(msg Struct_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE)
}

//Received_REL_TRU_TELL_TRANSCRIPT forward an REL_TRU_TELL_TRANSCRIPT message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_TRU_TELL_TRANSCRIPT(msg Struct_REL_TRU_TELL_TRANSCRIPT) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_TRU_TELL_TRANSCRIPT)
}

//Received_REL_TRU_TELL_RATE_CHANGE forward an REL_TRU_TELL_RATE_CHANGE message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_TRU_TELL_RATE_CHANGE(msg Struct_REL_TRU_TELL_RATE_CHANGE) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_TRU_TELL_RATE_CHANGE)
}

//Received_CLI_REL_QUERY forward an CLI_REL_QUERY message to PriFi's lib
func (p *PriFiSDAProtocol) Received_CLI_REL_QUERY(msg Struct_CLI_REL_QUERY) error {
	return p.prifiLibInstance.ReceivedMessage(msg.CLI_REL_QUERY)
}

//Received_REL_CLI_QUERY forward an REL_CLI_QUERY message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_CLI_QUERY(msg Struct_REL_CLI_QUERY) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_CLI_QUERY)
}

//Received_CLI_REL_BLAME forward an CLI_REL_BLAME message to PriFi's lib
func (p *PriFiSDAProtocol) Received_CLI_REL_BLAME(msg Struct_CLI_REL_BLAME) error {
	return p.prifiLibInstance.ReceivedMessage(msg.CLI_REL_BLAME)
}

//Received_REL_ALL_REVEAL forward an REL_ALL_REVEAL message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_ALL_REVEAL(msg Struct_REL_ALL_REVEAL) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_ALL_REVEAL)
}

//Received_CLI_REL_REVEAL forward an CLI_REL_REVEAL message to PriFi's lib
func (p *PriFiSDAProtocol) Received_CLI_REL_REVEAL(msg Struct_CLI_REL_REVEAL) error {
	return p.prifiLibInstance.ReceivedMessage(msg.CLI_REL_REVEAL)
}

//Received_TRU_REL_REVEAL forward an TRU_REL_REVEAL message to PriFi's lib
func (p *PriFiSDAProtocol) Received_TRU_REL_REVEAL(msg Struct_TRU_REL_REVEAL) error {
	return p.prifiLibInstance.ReceivedMessage(msg.TRU_REL_REVEAL)
}

//Received_REL_ALL_SECRET forward an REL_ALL_SECRET message to PriFi's lib
func (p *PriFiSDAProtocol) Received_REL_ALL_SECRET(msg Struct_REL_ALL_SECRET) error {
	return p.prifiLibInstance.ReceivedMessage(msg.REL_ALL_SECRET)
}

//Received_CLI_REL_SECRET forward an CLI_REL_SECRET message to PriFi's lib
func (p *PriFiSDAProtocol) Received_CLI_REL_SECRET(msg Struct_CLI_REL_SECRET) error {
	return p.prifiLibInstance.ReceivedMessage(msg.CLI_REL_SECRET)
}

//Received_TRU_REL_SECRET forward an TRU_REL_SECRET message to PriFi's lib
func (p *PriFiSDAProtocol) Received_TRU_REL_SECRET(msg Struct_TRU_REL_SECRET) error {
	return p.prifiLibInstance.ReceivedMessage(msg.TRU_REL_SECRET)
}
