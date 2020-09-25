package commands

import (
	cmds "github.com/ipfs/go-ipfs-cmds"
)

var retrievalClientCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Manage retrieval client operations",
	},
	Subcommands: map[string]*cmds.Command{
		"retrieve-piece": clientRetrievePieceCmd,
	},
}

var clientRetrievePieceCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Read out piece data stored by a miner on the network",
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("miner", true, false, "Retrieval miner actor address"),
		cmds.StringArg("cid", true, false, "Content identifier of piece to read"),
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		panic("TODO: go-fil-markets integration")

		//minerAddr, err := address.NewFromString(req.Arguments[0])
		//if err != nil {
		//	return err
		//}
		//
		//pieceCID, err := cid.Decode(req.Arguments[1])
		//if err != nil {
		//	return err
		//}
		//
		//mpid, err := GetPorcelainAPI(env).MinerGetPeerID(req.Context, minerAddr)
		//if err != nil {
		//	return err
		//}
		//
		//readCloser, err := GetRetrievalAPI(env).RetrievePiece(req.Context, pieceCID, mpid, minerAddr)
		//if err != nil {
		//	return err
		//}
		//
		//return re.Emit(readCloser)
	},
}
