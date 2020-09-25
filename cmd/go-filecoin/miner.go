package commands

import (
	"fmt"
	"math/big"

	address "github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-filecoin/vendors/sector-storage/ffiwrapper"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/specs-actors/actors/builtin"
	"github.com/filecoin-project/specs-actors/actors/builtin/miner"
	cid "github.com/ipfs/go-cid"
	cmds "github.com/ipfs/go-ipfs-cmds"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/pkg/errors"

	"github.com/filecoin-project/go-filecoin/internal/app/go-filecoin/porcelain"
	"github.com/filecoin-project/go-filecoin/internal/pkg/constants"
	"github.com/filecoin-project/go-filecoin/internal/pkg/types"
	"github.com/filecoin-project/go-filecoin/internal/pkg/vm/gas"
)

var minerCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Manage a single miner actor",
	},
	Subcommands: map[string]*cmds.Command{
		"create":        minerCreateCmd,
		"status":        minerStatusCommand,
		"set-price":     minerSetPriceCmd,
		"update-peerid": minerUpdatePeerIDCmd,
		"set-worker":    minerSetWorkerAddressCmd,
	},
}

// MinerCreateResult is the type returned when creating a miner.
type MinerCreateResult struct {
	Address address.Address
	GasUsed gas.Unit
	Preview bool
}

var minerCreateCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Create a new file miner with <collateral> FIL",
		ShortDescription: `Issues a new message to the network to create the miner, then waits for the
message to be mined as this is required to return the address of the new miner.
Collateral will be committed at the rate of 0.001FIL per sector. When the
miner's collateral drops below 0.001FIL, the miner will not be able to commit
additional sectors.`,
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("collateral", true, false, "The amount of collateral, in FIL."),
	},
	Options: []cmds.Option{
		cmds.StringOption("sectorsize", "size of the sectors which this miner will commit, in bytes"),
		cmds.StringOption("from", "address to send from"),
		cmds.StringOption("peerid", "Base58-encoded libp2p peer ID that the miner will operate"),
		feecapOption,
		premiumOption,
		limitOption,
		previewOption,
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		var err error

		sectorSize, err := optionalSectorSizeWithDefault(req.Options["sectorsize"], constants.DevSectorSize)
		if err != nil {
			return err
		}

		sealProofType, err := ffiwrapper.SealProofTypeFromSectorSize(sectorSize)
		if err != nil {
			return err
		}

		fromAddr, err := fromAddrOrDefault(req, env)
		if err != nil {
			return err
		}

		var pid peer.ID
		peerid := req.Options["peerid"]
		if peerid != nil {
			pid, err = peer.Decode(peerid.(string))
			if err != nil {
				return errors.Wrap(err, "invalid peer id")
			}
		}
		if pid == "" {
			pid = GetPorcelainAPI(env).NetworkGetPeerID()
		}

		collateral, ok := types.NewAttoFILFromFILString(req.Arguments[0])
		if !ok {
			return ErrInvalidCollateral
		}

		feecap, premium, gasLimit, preview, err := parseGasOptions(req)
		if err != nil {
			return err
		}

		if preview {
			usedGas, err := GetPorcelainAPI(env).MinerPreviewCreate(
				req.Context,
				fromAddr,
				sectorSize,
				pid,
			)
			if err != nil {
				return err
			}
			return re.Emit(&MinerCreateResult{
				Address: address.Undef,
				GasUsed: usedGas,
				Preview: true,
			})
		}

		addr, err := GetPorcelainAPI(env).MinerCreate(
			req.Context,
			fromAddr,
			feecap,
			premium,
			gasLimit,
			sealProofType,
			pid,
			collateral,
		)
		if err != nil {
			return errors.Wrap(err, "Could not create miner. Please consult the documentation to setup your wallet and genesis block correctly")
		}

		return re.Emit(&MinerCreateResult{
			Address: addr,
			GasUsed: gas.NewGas(0),
			Preview: false,
		})
	},
	Type: &MinerCreateResult{},
}

// MinerSetPriceResult is the return type for miner set-price command
type MinerSetPriceResult struct {
	MinerAddress address.Address
	Price        types.AttoFIL
}

var minerSetPriceCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Set the minimum price for storage",
		ShortDescription: `Sets the mining.minimumPrice in config and creates a new ask for the given price.
This command waits for the ask to be mined.`,
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("storageprice", true, false, "The new price of storage in FIL per byte per block"),
		cmds.StringArg("duration", true, false, "How long this ask is valid for in epochs"),
		cmds.StringArg("verified-price", true, false, "verify price"),
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		price, ok := types.NewAttoFILFromFILString(req.Arguments[0])
		if !ok {
			return ErrInvalidPrice
		}
		verifiedPrice, ok := types.NewAttoFILFromFILString(req.Arguments[0])
		if !ok {
			return ErrInvalidPrice
		}

		expiry, ok := big.NewInt(0).SetString(req.Arguments[1], 10)
		if !ok {
			return fmt.Errorf("expiry must be a valid integer")
		}

		err := GetStorageAPI(env).AddAsk(price, abi.ChainEpoch(expiry.Uint64()), verifiedPrice)
		if err != nil {
			return err
		}

		minerAddr, err := GetBlockAPI(env).MinerAddress()
		if err != nil {
			return err
		}

		return re.Emit(&MinerSetPriceResult{minerAddr, price})
	},
	Type: &MinerSetPriceResult{},
}

// MinerUpdatePeerIDResult is the return type for miner update-peerid command
type MinerUpdatePeerIDResult struct {
	Cid     cid.Cid
	GasUsed gas.Unit
	Preview bool
}

var minerUpdatePeerIDCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline:          "Change the libp2p identity that a miner is operating",
		ShortDescription: `Issues a new message to the network to update the miner's libp2p identity.`,
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("address", true, false, "Miner address to update peer ID for"),
		cmds.StringArg("peerid", true, false, "Base58-encoded libp2p peer ID that the miner will operate"),
	},
	Options: []cmds.Option{
		cmds.StringOption("from", "Address to send from"),
		feecapOption,
		premiumOption,
		limitOption,
		previewOption,
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		minerAddr, err := address.NewFromString(req.Arguments[0])
		if err != nil {
			return err
		}

		fromAddr, err := fromAddrOrDefault(req, env)
		if err != nil {
			return err
		}

		newPid, err := peer.Decode(req.Arguments[1])
		if err != nil {
			return err
		}

		feecap, premium, gasLimit, preview, err := parseGasOptions(req)
		if err != nil {
			return err
		}

		if preview {
			usedGas, err := GetPorcelainAPI(env).MessagePreview(
				req.Context,
				fromAddr,
				minerAddr,
				builtin.MethodsMiner.ChangePeerID,
				newPid,
			)
			if err != nil {
				return err
			}

			return re.Emit(&MinerUpdatePeerIDResult{
				Cid:     cid.Cid{},
				GasUsed: usedGas,
				Preview: true,
			})
		}

		params := miner.ChangePeerIDParams{NewID: abi.PeerID(newPid)}

		c, _, err := GetPorcelainAPI(env).MessageSend(
			req.Context,
			fromAddr,
			minerAddr,
			types.ZeroAttoFIL,
			feecap,
			premium,
			gasLimit,
			builtin.MethodsMiner.ChangePeerID,
			&params,
		)
		if err != nil {
			return err
		}

		return re.Emit(&MinerUpdatePeerIDResult{
			Cid:     c,
			GasUsed: gas.NewGas(0),
			Preview: false,
		})
	},
	Type: &MinerUpdatePeerIDResult{},
}

var minerStatusCommand = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Get the status of a miner",
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		minerAddr, err := optionalAddr(req.Arguments[0])
		if err != nil {
			return err
		}

		porcelainAPI := GetPorcelainAPI(env)
		status, err := porcelainAPI.MinerGetStatus(req.Context, minerAddr, porcelainAPI.ChainHeadKey())
		if err != nil {
			return err
		}
		return re.Emit(status)
	},
	Type: porcelain.MinerStatus{},
	Arguments: []cmds.Argument{
		cmds.StringArg("miner", true, false, "A miner actor address"),
	},
}

var minerSetWorkerAddressCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline:          "Set the address of the miner worker. Returns a message CID",
		ShortDescription: "Set the address of the miner worker to the provided address. When a miner is created, this address defaults to the miner owner. Use this command to change the default. Returns a message CID to wait for the message to appear on chain.",
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("new-address", true, false, "The address of the new miner worker."),
	},
	Options: []cmds.Option{
		feecapOption,
		premiumOption,
		limitOption,
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		newWorker, err := address.NewFromString(req.Arguments[0])
		if err != nil {
			return err
		}

		feecap, premium, gasLimit, _, err := parseGasOptions(req)
		if err != nil {
			return err
		}

		msgCid, err := GetPorcelainAPI(env).MinerSetWorkerAddress(req.Context, newWorker, feecap, premium, gasLimit)
		if err != nil {
			return err
		}

		return re.Emit(msgCid)
	},
	Type: cid.Cid{},
}
