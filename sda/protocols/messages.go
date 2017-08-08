package protocols

import (
	"github.com/lbarman/prifi/prifi-lib/net"
	"gopkg.in/dedis/onet.v1"
)

//Struct_ALL_ALL_SHUTDOWN is a wrapper for ALL_ALL_SHUTDOWN (but also contains a *onet.TreeNode)
type Struct_ALL_ALL_SHUTDOWN struct {
	*onet.TreeNode
	net.ALL_ALL_SHUTDOWN
}

//Struct_ALL_ALL_PARAMETERS is a wrapper for ALL_ALL_PARAMETERS_NEW (but also contains a *onet.TreeNode)
type Struct_ALL_ALL_PARAMETERS_NEW struct {
	*onet.TreeNode
	net.ALL_ALL_PARAMETERS_NEW
}

//Struct_CLI_REL_TELL_PK_AND_EPH_PK is a wrapper for CLI_REL_TELL_PK_AND_EPH_PK (but also contains a *onet.TreeNode)
type Struct_CLI_REL_TELL_PK_AND_EPH_PK struct {
	*onet.TreeNode
	net.CLI_REL_TELL_PK_AND_EPH_PK
}

//Struct_CLI_REL_UPSTREAM_DATA is a wrapper for CLI_REL_UPSTREAM_DATA (but also contains a *onet.TreeNode)
type Struct_CLI_REL_UPSTREAM_DATA struct {
	*onet.TreeNode
	net.CLI_REL_UPSTREAM_DATA
}

//Struct_CLI_REL_UPSTREAM_DATA is a wrapper for CLI_REL_OPENCLOSED_DATA (but also contains a *onet.TreeNode)
type Struct_CLI_REL_OPENCLOSED_DATA struct {
	*onet.TreeNode
	net.CLI_REL_OPENCLOSED_DATA
}

//Struct_REL_CLI_DOWNSTREAM_DATA is a wrapper for REL_CLI_DOWNSTREAM_DATA (but also contains a *onet.TreeNode)
type Struct_REL_CLI_DOWNSTREAM_DATA struct {
	*onet.TreeNode
	net.REL_CLI_DOWNSTREAM_DATA
}

//Struct_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG is a wrapper for REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG (but also contains a *onet.TreeNode)
type Struct_REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG struct {
	*onet.TreeNode
	net.REL_CLI_TELL_EPH_PKS_AND_TRUSTEES_SIG
}

//Struct_REL_CLI_TELL_TRUSTEES_PK is a wrapper for REL_CLI_TELL_TRUSTEES_PK (but also contains a *onet.TreeNode)
type Struct_REL_CLI_TELL_TRUSTEES_PK struct {
	*onet.TreeNode
	net.REL_CLI_TELL_TRUSTEES_PK
}

//Struct_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE is a wrapper for REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE (but also contains a *onet.TreeNode)
type Struct_REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE struct {
	*onet.TreeNode
	net.REL_TRU_TELL_CLIENTS_PKS_AND_EPH_PKS_AND_BASE
}

//Struct_REL_TRU_TELL_TRANSCRIPT is a wrapper for REL_TRU_TELL_TRANSCRIPT (but also contains a *onet.TreeNode)
type Struct_REL_TRU_TELL_TRANSCRIPT struct {
	*onet.TreeNode
	net.REL_TRU_TELL_TRANSCRIPT
}

//Struct_TRU_REL_DC_CIPHER is a wrapper for TRU_REL_DC_CIPHER (but also contains a *onet.TreeNode)
type Struct_TRU_REL_DC_CIPHER struct {
	*onet.TreeNode
	net.TRU_REL_DC_CIPHER
}

//Struct_TRU_REL_SHUFFLE_SIG is a wrapper for TRU_REL_SHUFFLE_SIG (but also contains a *onet.TreeNode)
type Struct_TRU_REL_SHUFFLE_SIG struct {
	*onet.TreeNode
	net.TRU_REL_SHUFFLE_SIG
}

//Struct_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS is a wrapper for TRU_REL_TELL_NEW_BASE_AND_EPH_PKS (but also contains a *onet.TreeNode)
type Struct_TRU_REL_TELL_NEW_BASE_AND_EPH_PKS struct {
	*onet.TreeNode
	net.TRU_REL_TELL_NEW_BASE_AND_EPH_PKS
}

//Struct_TRU_REL_TELL_PK is a wrapper for TRU_REL_TELL_PK (but also contains a *onet.TreeNode)
type Struct_TRU_REL_TELL_PK struct {
	*onet.TreeNode
	net.TRU_REL_TELL_PK
}

//Struct_REL_TRU_TELL_RATE_CHANGE is a wrapper for REL_TRU_TELL_RATE_CHANGE (but also contains a *onet.TreeNode)
type Struct_REL_TRU_TELL_RATE_CHANGE struct {
	*onet.TreeNode
	net.REL_TRU_TELL_RATE_CHANGE
}

//Struct_REL_CLI_DISRUPTED_ROUND is a wrapper for REL_CLI_DISRUPTED_ROUND (but also contains a *onet.TreeNode)
type Struct_REL_CLI_DISRUPTED_ROUND struct {
	*onet.TreeNode
	net.REL_CLI_DISRUPTED_ROUND
}

//Struct_CLI_REL_DISRUPTION_BLAME is a wrapper for CLI_REL_DISRUPTION_BLAME (but also contains a *onet.TreeNode)
type Struct_CLI_REL_DISRUPTION_BLAME struct {
	*onet.TreeNode
	net.CLI_REL_DISRUPTION_BLAME
}

//Struct_REL_ALL_DISRUPTION_REVEAL is a wrapper for REL_ALL_DISRUPTION_REVEAL (but also contains a *onet.TreeNode)
type Struct_REL_ALL_DISRUPTION_REVEAL struct {
	*onet.TreeNode
	net.REL_ALL_DISRUPTION_REVEAL
}

//Struct_CLI_REL_DISRUPTION_REVEAL is a wrapper for CLI_REL_DISRUPTION_REVEAL (but also contains a *onet.TreeNode)
type Struct_CLI_REL_DISRUPTION_REVEAL struct {
	*onet.TreeNode
	net.CLI_REL_DISRUPTION_REVEAL
}

//Struct_TRU_REL_DISRUPTION_REVEAL is a wrapper for TRU_REL_DISRUPTION_REVEAL (but also contains a *onet.TreeNode)
type Struct_TRU_REL_DISRUPTION_REVEAL struct {
	*onet.TreeNode
	net.TRU_REL_DISRUPTION_REVEAL
}

//Struct_REL_ALL_DISRUPTION_SECRET is a wrapper for REL_ALL_DISRUPTION_SECRET (but also contains a *onet.TreeNode)
type Struct_REL_ALL_DISRUPTION_SECRET struct {
	*onet.TreeNode
	net.REL_ALL_DISRUPTION_SECRET
}

//Struct_CLI_REL_DISRUPTION_SECRET is a wrapper for CLI_REL_DISRUPTION_SECRET (but also contains a *onet.TreeNode)
type Struct_CLI_REL_DISRUPTION_SECRET struct {
	*onet.TreeNode
	net.CLI_REL_DISRUPTION_SECRET
}

//Struct_TRU_REL_DISRUPTION_SECRET is a wrapper for TRU_REL_DISRUPTION_SECRET (but also contains a *onet.TreeNode)
type Struct_TRU_REL_DISRUPTION_SECRET struct {
	*onet.TreeNode
	net.TRU_REL_DISRUPTION_SECRET
}
