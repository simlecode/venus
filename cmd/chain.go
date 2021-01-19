// Package commands implements the command to print the blockchain.
package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/ipfs/go-cid"
	cmds "github.com/ipfs/go-ipfs-cmds"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/venus/app/node"
	"github.com/filecoin-project/venus/app/submodule/chain"
	"github.com/filecoin-project/venus/pkg/block"
	syncTypes "github.com/filecoin-project/venus/pkg/chainsync/types"
	"github.com/filecoin-project/venus/pkg/types"
)

var chainCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Inspect the filecoin blockchain",
	},
	Subcommands: map[string]*cmds.Command{
		"export":   chainExportCmd,
		"head":     chainHeadCmd,
		"ls":       chainLsCmd,
		"status":   chainStatusCmd,
		"set-head": chainSetHeadCmd,
		"getblock": chainGetBlockCmd,
	},
}

type ChainHeadResult struct {
	Height       abi.ChainEpoch
	ParentWeight big.Int
	Cids         []cid.Cid
	Timestamp    string
}

var chainHeadCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Get heaviest tipset info",
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		head, err := env.(*node.Env).ChainAPI.ChainHead(req.Context)
		if err != nil {
			return err
		}

		h, err := head.Height()
		if err != nil {
			return err
		}

		pw, err := head.ParentWeight()
		if err != nil {
			return err
		}

		strTt := time.Unix(int64(head.MinTimestamp()), 0).Format("2006-01-02 15:04:05")

		return re.Emit(&ChainHeadResult{Height: h, ParentWeight: pw, Cids: head.Key().Cids(), Timestamp: strTt})
	},
	Type: &ChainHeadResult{},
}

type BlockResult struct {
	Cid   cid.Cid
	Miner address.Address
}

type ChainLsResult struct {
	Height    abi.ChainEpoch
	Timestamp string
	Blocks    []BlockResult
}

var chainLsCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline:          "List blocks in the blockchain",
		ShortDescription: `Provides a list of blocks in order from head to genesis. By default, only CIDs are returned for each block.`,
	},
	Options: []cmds.Option{
		cmds.Int64Option("height", "Start height of the query").WithDefault(-1),
		cmds.UintOption("count", "Number of queries").WithDefault(10),
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		count, _ := req.Options["count"].(uint)
		if count < 1 {
			return nil
		}

		var err error
		height, _ := req.Options["height"].(int64)
		startTs, err := env.(*node.Env).ChainAPI.ChainHead(req.Context)
		if err != nil {
			return err
		}
		if height >= 0 {
			startTs, err = env.(*node.Env).ChainAPI.ChainGetTipSetByHeight(req.Context, abi.ChainEpoch(height), startTs.Key())
			if err != nil {
				return err
			}
		}

		tipSetKeys, err := env.(*node.Env).ChainAPI.ChainList(req.Context, startTs.Key(), int(count))
		if err != nil {
			return err
		}

		res := make([]ChainLsResult, 0)
		for _, key := range tipSetKeys {
			tp, err := env.(*node.Env).ChainAPI.ChainGetTipSet(key)
			if err != nil {
				return err
			}

			h, err := tp.Height()
			if err != nil {
				return err
			}

			strTt := time.Unix(int64(tp.MinTimestamp()), 0).Format("2006-01-02 15:04:05")

			blks := make([]BlockResult, len(tp.Blocks()))
			for idx, blk := range tp.Blocks() {
				blks[idx] = BlockResult{Cid: blk.Cid(), Miner: blk.Miner}
			}

			lsRes := ChainLsResult{Height: h, Timestamp: strTt, Blocks: blks}
			res = append(res, lsRes)
		}

		if err := re.Emit(res); err != nil {
			return err
		}
		return nil
	},
	Type: []ChainLsResult{},
}

type SyncTarget struct {
	TargetTs block.TipSetKey
	Height   abi.ChainEpoch
	State    string
}

type SyncStatus struct {
	Target []SyncTarget
}

var chainStatusCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Show status of chain sync operation.",
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		//TODO give each target a status
		//syncStatus.Status = env.(*node.Env).SyncerAPI.SyncerStatus()
		tracker := env.(*node.Env).SyncerAPI.SyncerTracker()
		targets := tracker.Buckets()
		w := bytes.NewBufferString("")
		writer := NewSilentWriter(w)
		for index, t := range targets {
			writer.Println("SyncTarget:", strconv.Itoa(index+1))
			writer.Println("\tBase:", t.Base.EnsureHeight(), t.Base.Key().String())

			writer.Println("\tTarget:", t.Head.EnsureHeight(), t.Head.Key().String())

			if t.Current != nil {
				writer.Println("\tCurrent:", t.Current.EnsureHeight(), t.Current.Key().String())
			} else {
				writer.Println("\tCurrent:")
			}

			if t.State != syncTypes.StageIdle {
				writer.Println("\tStatus:Syncing")
			} else {
				writer.Println("\tStatus:Wait")
			}
			writer.Println("\tErr:", t.Err)
			writer.Println()
		}
		history := tracker.History()
		count := len(targets)
		for target := history.Front(); target != nil; target = target.Next() {
			t := target.Value.(*syncTypes.Target)
			writer.Println("SyncTarget:", strconv.Itoa(count+1))
			writer.Println("\tBase:", t.Base.EnsureHeight(), t.Base.Key().String())

			writer.Println("\tTarget:", t.Head.EnsureHeight(), t.Head.Key().String())

			if t.Current != nil {
				writer.Println("\tCurrent:", t.Current.EnsureHeight(), t.Current.Key().String())
			} else {
				writer.Println("\tCurrent:")
			}

			if t.State != syncTypes.StageIdle {
				writer.Println("\tStatus:Syncing")
			} else {
				writer.Println("\tStatus:Wait")
			}

			writer.Println("\tErr:", t.Err)
			count++
			writer.Println()
		}

		if err := re.Emit(w); err != nil {
			return err
		}
		return nil
	},
}

var chainSetHeadCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Set the chain head to a specific tipset key.",
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("cids", true, true, "CID's of the blocks of the tipset to set the chain head to."),
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		headCids, err := cidsFromSlice(req.Arguments)
		if err != nil {
			return err
		}
		maybeNewHead := block.NewTipSetKey(headCids...)
		return env.(*node.Env).ChainAPI.ChainSetHead(req.Context, maybeNewHead)
	},
}

var chainExportCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Export the chain store to a car file.",
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("file", true, false, "File to export chain data to."),
		cmds.StringArg("cids", true, true, "CID's of the blocks of the tipset to export from."),
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		f, err := os.Create(req.Arguments[0])
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		expCids, err := cidsFromSlice(req.Arguments[1:])
		if err != nil {
			return err
		}
		expKey := block.NewTipSetKey(expCids...)

		if err := env.(*node.Env).ChainAPI.ChainExport(req.Context, expKey, f); err != nil {
			return err
		}
		return nil
	},
}

var chainGetBlockCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Get a block and print its details.",
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("cid", true, true, "CID of the block to show."),
	},
	Options: []cmds.Option{
		cmds.BoolOption("raw", "print just the raw block header"),
	},
	Run: func(req *cmds.Request, re cmds.ResponseEmitter, env cmds.Environment) error {
		bcid, err := cid.Decode(req.Arguments[0])
		if err != nil {
			return err
		}

		ctx := req.Context
		blk, err := env.(*node.Env).ChainAPI.ChainGetBlock(ctx, bcid)
		if err != nil {
			return xerrors.Errorf("get block failed: %w", err)
		}

		buf := new(bytes.Buffer)
		writer := NewSilentWriter(buf)

		if _, ok := req.Options["raw"].(bool); ok {
			out, err := json.MarshalIndent(blk, "", "  ")
			if err != nil {
				return err
			}

			_ = writer.Write(out)

			return re.Emit(buf)
		}

		msgs, err := env.(*node.Env).ChainAPI.ChainGetBlockMessages(ctx, bcid)
		if err != nil {
			return xerrors.Errorf("failed to get messages: %v", err)
		}

		pmsgs, err := env.(*node.Env).ChainAPI.ChainGetParentMessages(ctx, bcid)
		if err != nil {
			return xerrors.Errorf("failed to get parent messages: %v", err)
		}

		recpts, err := env.(*node.Env).ChainAPI.ChainGetParentReceipts(ctx, bcid)
		if err != nil {
			log.Warn(err)
		}

		cblock := struct {
			block.Block
			BlsMessages    []*types.UnsignedMessage
			SecpkMessages  []*types.SignedMessage
			ParentReceipts []*types.MessageReceipt
			ParentMessages []cid.Cid
		}{}

		cblock.Block = *blk
		cblock.BlsMessages = msgs.BlsMessages
		cblock.SecpkMessages = msgs.SecpkMessages
		cblock.ParentReceipts = recpts
		cblock.ParentMessages = apiMsgCids(pmsgs)

		out, err := json.MarshalIndent(cblock, "", "  ")
		if err != nil {
			return err
		}

		_ = writer.Write(out)

		return re.Emit(buf)
	},
}

func apiMsgCids(in []chain.Message) []cid.Cid {
	out := make([]cid.Cid, len(in))
	for k, v := range in {
		out[k] = v.Cid
	}
	return out
}
