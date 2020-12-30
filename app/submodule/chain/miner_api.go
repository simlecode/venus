package chain

import (
	"context"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-bitfield"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/go-state-types/dline"
	"github.com/ipfs/go-cid"
	xerrors "github.com/pkg/errors"

	"github.com/filecoin-project/venus/pkg/block"
	"github.com/filecoin-project/venus/pkg/chain"
	"github.com/filecoin-project/venus/pkg/specactors/builtin"
	"github.com/filecoin-project/venus/pkg/specactors/builtin/market"
	"github.com/filecoin-project/venus/pkg/specactors/builtin/miner"
	"github.com/filecoin-project/venus/pkg/specactors/builtin/power"
	"github.com/filecoin-project/venus/pkg/specactors/builtin/reward"
	"github.com/filecoin-project/venus/pkg/types"
	"github.com/filecoin-project/venus/pkg/vm/state"
)

type MinerStateAPI struct {
	chain *ChainSubmodule
}

func NewMinerStateAPI(chain *ChainSubmodule) MinerStateAPI {
	return MinerStateAPI{chain: chain}
}

func (minerStateAPI *MinerStateAPI) StateMinerSectorAllocated(ctx context.Context, maddr address.Address, s abi.SectorNumber, tsk block.TipSetKey) (bool, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return false, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	mas, err := view.LoadMinerState(ctx, maddr)
	if err != nil {
		return false, xerrors.Errorf("failed to load miner actor state: %v", err)
	}
	return mas.IsAllocated(s)
}

func (minerStateAPI *MinerStateAPI) StateSectorPreCommitInfo(ctx context.Context, maddr address.Address, n abi.SectorNumber, tsk block.TipSetKey) (miner.SectorPreCommitOnChainInfo, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return miner.SectorPreCommitOnChainInfo{}, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	pci, err := view.PreCommitInfo(ctx, maddr, n)
	if err != nil {
		return miner.SectorPreCommitOnChainInfo{}, err
	} else if pci == nil {
		return miner.SectorPreCommitOnChainInfo{}, xerrors.Errorf("precommit info is not exists")
	}
	return *pci, nil
}

func (minerStateAPI *MinerStateAPI) StateSectorGetInfo(ctx context.Context, maddr address.Address, n abi.SectorNumber, tsk block.TipSetKey) (*miner.SectorOnChainInfo, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	return view.MinerSectorInfo(ctx, maddr, n)
}

func (minerStateAPI *MinerStateAPI) StateSectorPartition(ctx context.Context, maddr address.Address, sectorNumber abi.SectorNumber, tsk block.TipSetKey) (*miner.SectorLocation, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	return view.StateSectorPartition(ctx, maddr, sectorNumber)
}

func (minerStateAPI *MinerStateAPI) StateMinerSectorSize(ctx context.Context, maddr address.Address, tsk block.TipSetKey) (abi.SectorSize, error) {
	// TODO: update storage-fsm to just StateMinerSectorAllocated
	mi, err := minerStateAPI.StateMinerInfo(ctx, maddr, tsk)
	if err != nil {
		return 0, err
	}
	return mi.SectorSize, nil
}

func (minerStateAPI *MinerStateAPI) StateMinerInfo(ctx context.Context, maddr address.Address, tsk block.TipSetKey) (miner.MinerInfo, error) {
	ts, err := minerStateAPI.chain.State.GetTipSet(tsk)
	if err != nil {
		return miner.MinerInfo{}, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return miner.MinerInfo{}, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	nv := minerStateAPI.chain.Fork.GetNtwkVersion(ctx, ts.EnsureHeight())
	minfo, err := view.MinerInfo(ctx, maddr, nv)
	if err != nil {
		return miner.MinerInfo{}, err
	}
	return *minfo, nil
}

func (minerStateAPI *MinerStateAPI) StateMinerWorkerAddress(ctx context.Context, maddr address.Address, tsk block.TipSetKey) (address.Address, error) {
	// TODO: update storage-fsm to just StateMinerInfo
	mi, err := minerStateAPI.StateMinerInfo(ctx, maddr, tsk)
	if err != nil {
		return address.Undef, err
	}
	return mi.Worker, nil
}

func (minerStateAPI *MinerStateAPI) StateMinerRecoveries(ctx context.Context, maddr address.Address, tsk block.TipSetKey) (bitfield.BitField, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return bitfield.BitField{}, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	mas, err := view.LoadMinerState(ctx, maddr)
	if err != nil {
		return bitfield.BitField{}, xerrors.Errorf("failed to load miner actor state: %v", err)
	}

	return miner.AllPartSectors(mas, miner.Partition.RecoveringSectors)
}

func (minerStateAPI *MinerStateAPI) StateMinerFaults(ctx context.Context, maddr address.Address, tsk block.TipSetKey) (bitfield.BitField, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return bitfield.BitField{}, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	mas, err := view.LoadMinerState(ctx, maddr)
	if err != nil {
		return bitfield.BitField{}, xerrors.Errorf("failed to load miner actor state: %v", err)
	}

	return miner.AllPartSectors(mas, miner.Partition.FaultySectors)
}

func (minerStateAPI *MinerStateAPI) StateMinerProvingDeadline(ctx context.Context, maddr address.Address, tsk block.TipSetKey) (*dline.Info, error) {
	ts, err := minerStateAPI.chain.ChainReader.GetTipSet(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	mas, err := view.LoadMinerState(ctx, maddr)
	if err != nil {
		return nil, xerrors.Errorf("failed to load miner actor state: %v", err)
	}
	di, err := mas.DeadlineInfo(ts.EnsureHeight())
	if err != nil {
		return nil, xerrors.Errorf("failed to get deadline info: %v", err)
	}

	return di.NextNotElapsed(), nil
}

func (minerStateAPI *MinerStateAPI) StateMinerPartitions(ctx context.Context, maddr address.Address, dlIdx uint64, tsk block.TipSetKey) ([]Partition, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	mas, err := view.LoadMinerState(ctx, maddr)
	if err != nil {
		return nil, xerrors.Errorf("failed to load miner actor state: %v", err)
	}

	dl, err := mas.LoadDeadline(dlIdx)
	if err != nil {
		return nil, xerrors.Errorf("failed to load the deadline: %v", err)
	}

	var out []Partition
	err = dl.ForEachPartition(func(_ uint64, part miner.Partition) error {
		allSectors, err := part.AllSectors()
		if err != nil {
			return xerrors.Errorf("getting AllSectors: %v", err)
		}

		faultySectors, err := part.FaultySectors()
		if err != nil {
			return xerrors.Errorf("getting FaultySectors: %v", err)
		}

		recoveringSectors, err := part.RecoveringSectors()
		if err != nil {
			return xerrors.Errorf("getting RecoveringSectors: %v", err)
		}

		liveSectors, err := part.LiveSectors()
		if err != nil {
			return xerrors.Errorf("getting LiveSectors: %v", err)
		}

		activeSectors, err := part.ActiveSectors()
		if err != nil {
			return xerrors.Errorf("getting ActiveSectors: %v", err)
		}

		out = append(out, Partition{
			AllSectors:        allSectors,
			FaultySectors:     faultySectors,
			RecoveringSectors: recoveringSectors,
			LiveSectors:       liveSectors,
			ActiveSectors:     activeSectors,
		})
		return nil
	})

	return out, err
}

func (minerStateAPI *MinerStateAPI) StateMinerDeadlines(ctx context.Context, maddr address.Address, tsk block.TipSetKey) ([]Deadline, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	mas, err := view.LoadMinerState(ctx, maddr)
	if err != nil {
		return nil, xerrors.Errorf("failed to load miner actor state: %v", err)
	}

	deadlines, err := mas.NumDeadlines()
	if err != nil {
		return nil, xerrors.Errorf("getting deadline count: %v", err)
	}

	out := make([]Deadline, deadlines)
	if err := mas.ForEachDeadline(func(i uint64, dl miner.Deadline) error {
		ps, err := dl.PostSubmissions()
		if err != nil {
			return err
		}

		out[i] = Deadline{
			PostSubmissions: ps,
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (minerStateAPI *MinerStateAPI) StateMinerSectors(ctx context.Context, maddr address.Address, sectorNos *bitfield.BitField, tsk block.TipSetKey) ([]*miner.SectorOnChainInfo, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	mas, err := view.LoadMinerState(ctx, maddr)
	if err != nil {
		return nil, xerrors.Errorf("failed to load miner actor state: %v", err)
	}

	return mas.LoadSectors(sectorNos)
}

func (minerStateAPI *MinerStateAPI) StateMarketStorageDeal(ctx context.Context, dealID abi.DealID, tsk block.TipSetKey) (*MarketDeal, error) {
	view, err := minerStateAPI.chain.State.ParentStateView(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading view %s: %v", tsk, err)
	}

	mas, err := view.LoadMarketState(ctx)
	if err != nil {
		return nil, xerrors.Errorf("failed to load miner actor state: %v", err)
	}

	proposals, err := mas.Proposals()
	if err != nil {
		return nil, err
	}

	proposal, found, err := proposals.Get(dealID)

	if err != nil {
		return nil, err
	} else if !found {
		return nil, xerrors.Errorf("deal %d not found", dealID)
	}

	states, err := mas.States()
	if err != nil {
		return nil, err
	}

	st, found, err := states.Get(dealID)
	if err != nil {
		return nil, err
	}

	if !found {
		st = market.EmptyDealState()
	}

	return &MarketDeal{
		Proposal: *proposal,
		State:    *st,
	}, nil
}

var initialPledgeNum = big.NewInt(110)
var initialPledgeDen = big.NewInt(100)

func (minerStateAPI *MinerStateAPI) StateMinerPreCommitDepositForPower(ctx context.Context, maddr address.Address, pci miner.SectorPreCommitInfo, tsk block.TipSetKey) (big.Int, error) {
	store := minerStateAPI.chain.State.Store(ctx)
	ts, err := minerStateAPI.chain.ChainReader.GetTipSet(tsk)
	if err != nil {
		return big.Int{}, err
	}

	sTree, err := state.LoadState(ctx, store, ts.At(0).ParentStateRoot)
	if err != nil {
		return big.Int{}, err
	}

	ssize, err := pci.SealProof.SectorSize()
	if err != nil {
		return big.Int{}, xerrors.Errorf("failed to get resolve size: %v", err)
	}

	var sectorWeight abi.StoragePower
	if act, found, err := sTree.GetActor(ctx, market.Address); err != nil || !found {
		return big.Int{}, xerrors.Errorf("loading market actor %s: %v", maddr, err)
	} else if s, err := market.Load(store, act); err != nil {
		return big.Int{}, xerrors.Errorf("loading market actor state %s: %v", maddr, err)
	} else if w, vw, err := s.VerifyDealsForActivation(maddr, pci.DealIDs, ts.EnsureHeight(), pci.Expiration); err != nil {
		return big.Int{}, xerrors.Errorf("verifying deals for activation: %v", err)
	} else {
		// NB: not exactly accurate, but should always lead us to *over* estimate, not under
		duration := pci.Expiration - ts.EnsureHeight()
		sectorWeight = builtin.QAPowerForWeight(ssize, duration, w, vw)
	}

	var powerSmoothed builtin.FilterEstimate
	if act, found, err := sTree.GetActor(ctx, power.Address); err != nil || !found {
		return big.Int{}, xerrors.Errorf("loading power actor: %v", err)
	} else if s, err := power.Load(store, act); err != nil {
		return big.Int{}, xerrors.Errorf("loading power actor state: %v", err)
	} else if p, err := s.TotalPowerSmoothed(); err != nil {
		return big.Int{}, xerrors.Errorf("failed to determine total power: %v", err)
	} else {
		powerSmoothed = p
	}

	rewardActor, found, err := sTree.GetActor(ctx, reward.Address)
	if err != nil || !found {
		return big.Int{}, xerrors.Errorf("loading miner actor: %v", err)
	}

	rewardState, err := reward.Load(store, rewardActor)
	if err != nil {
		return big.Int{}, xerrors.Errorf("loading reward actor state: %v", err)
	}

	deposit, err := rewardState.PreCommitDepositForPower(powerSmoothed, sectorWeight)
	if err != nil {
		return big.Zero(), xerrors.Errorf("calculating precommit deposit: %v", err)
	}

	return big.Div(big.Mul(deposit, initialPledgeNum), initialPledgeDen), nil
}

func (minerStateAPI *MinerStateAPI) StateMinerInitialPledgeCollateral(ctx context.Context, maddr address.Address, pci miner.SectorPreCommitInfo, tsk block.TipSetKey) (big.Int, error) {
	// TODO: this repeats a lot of the previous function. Fix that.
	ts, err := minerStateAPI.chain.ChainReader.GetTipSet(tsk)
	if err != nil {
		return big.Int{}, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	store := minerStateAPI.chain.State.Store(ctx)
	state, err := state.LoadState(ctx, store, ts.At(0).ParentStateRoot)
	if err != nil {
		return big.Int{}, xerrors.Errorf("loading state %s: %v", tsk, err)
	}

	ssize, err := pci.SealProof.SectorSize()
	if err != nil {
		return big.Int{}, xerrors.Errorf("failed to get resolve size: %v", err)
	}

	var sectorWeight abi.StoragePower
	if act, found, err := state.GetActor(ctx, market.Address); err != nil || !found {
		return big.Int{}, xerrors.Errorf("loading miner actor %s: %v", maddr, err)
	} else if s, err := market.Load(store, act); err != nil {
		return big.Int{}, xerrors.Errorf("loading market actor state %s: %v", maddr, err)
	} else if w, vw, err := s.VerifyDealsForActivation(maddr, pci.DealIDs, ts.EnsureHeight(), pci.Expiration); err != nil {
		return big.Int{}, xerrors.Errorf("verifying deals for activation: %v", err)
	} else {
		// NB: not exactly accurate, but should always lead us to *over* estimate, not under
		duration := pci.Expiration - ts.EnsureHeight()
		sectorWeight = builtin.QAPowerForWeight(ssize, duration, w, vw)
	}

	var (
		powerSmoothed    builtin.FilterEstimate
		pledgeCollateral abi.TokenAmount
	)
	if act, found, err := state.GetActor(ctx, power.Address); err != nil || !found {
		return big.Int{}, xerrors.Errorf("loading miner actor: %v", err)
	} else if s, err := power.Load(store, act); err != nil {
		return big.Int{}, xerrors.Errorf("loading power actor state: %v", err)
	} else if p, err := s.TotalPowerSmoothed(); err != nil {
		return big.Int{}, xerrors.Errorf("failed to determine total power: %v", err)
	} else if c, err := s.TotalLocked(); err != nil {
		return big.Int{}, xerrors.Errorf("failed to determine pledge collateral: %v", err)
	} else {
		powerSmoothed = p
		pledgeCollateral = c
	}

	rewardActor, found, err := state.GetActor(ctx, reward.Address)
	if err != nil || !found {
		return big.Int{}, xerrors.Errorf("loading miner actor: %v", err)
	}

	rewardState, err := reward.Load(store, rewardActor)
	if err != nil {
		return big.Int{}, xerrors.Errorf("loading reward actor state: %v", err)
	}

	circSupply, err := minerStateAPI.StateVMCirculatingSupplyInternal(ctx, ts.Key())
	if err != nil {
		return big.Zero(), xerrors.Errorf("getting circulating supply: %v", err)
	}

	initialPledge, err := rewardState.InitialPledgeForPower(
		sectorWeight,
		pledgeCollateral,
		&powerSmoothed,
		circSupply.FilCirculating,
	)
	if err != nil {
		return big.Zero(), xerrors.Errorf("calculating initial pledge: %v", err)
	}

	return big.Div(big.Mul(initialPledge, initialPledgeNum), initialPledgeDen), nil
}

func (minerStateAPI *MinerStateAPI) StateVMCirculatingSupplyInternal(ctx context.Context, tsk block.TipSetKey) (chain.CirculatingSupply, error) {
	store := minerStateAPI.chain.State.Store(ctx)
	ts, err := minerStateAPI.chain.ChainReader.GetTipSet(tsk)
	if err != nil {
		return chain.CirculatingSupply{}, err
	}

	root, err := minerStateAPI.chain.State.GetTipSetStateRoot(ctx, tsk)
	if err != nil {
		return chain.CirculatingSupply{}, err
	}

	sTree, err := state.LoadState(ctx, store, root)
	if err != nil {
		return chain.CirculatingSupply{}, err
	}

	return minerStateAPI.chain.ChainReader.GetCirculatingSupplyDetailed(ctx, ts.EnsureHeight(), sTree)
}

func (minerStateAPI *MinerStateAPI) StateCirculatingSupply(ctx context.Context, tsk block.TipSetKey) (abi.TokenAmount, error) {
	return minerStateAPI.chain.ChainReader.StateCirculatingSupply(ctx, tsk)
}

func (minerStateAPI *MinerStateAPI) StateLookupID(ctx context.Context, addr address.Address, tsk block.TipSetKey) (address.Address, error) {
	if tsk.IsEmpty() {
		tsk = minerStateAPI.chain.ChainReader.GetHead()
	}

	state, err := minerStateAPI.chain.State.GetTipSetState(ctx, tsk)
	if err != nil {
		return address.Undef, xerrors.Errorf("load state tree: %v", err)
	}

	return state.LookupID(addr)
}

func (minerStateAPI *MinerStateAPI) StateListMiners(ctx context.Context, tsk block.TipSetKey) ([]address.Address, error) {
	if tsk.IsEmpty() {
		tsk = minerStateAPI.chain.ChainReader.GetHead()
	}
	ts, err := minerStateAPI.chain.ChainReader.GetTipSet(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	store := minerStateAPI.chain.State.Store(ctx)
	state, err := state.LoadState(ctx, store, ts.Blocks()[0].ParentStateRoot)
	if err != nil {
		return nil, xerrors.Errorf("loading state: %v", err)
	}

	act, found, err := state.GetActor(ctx, power.Address)
	if err != nil {
		return nil, xerrors.Errorf("failed to load power actor: %v", err)
	}
	if !found {
		return nil, xerrors.Errorf("actor not found for %v", power.Address)
	}

	powState, err := power.Load(store, act)
	if err != nil {
		return nil, xerrors.Errorf("failed to load power actor state: %v", err)
	}

	return powState.ListAllMiners()
}

func (minerStateAPI *MinerStateAPI) StateListActors(ctx context.Context, tsk block.TipSetKey) ([]address.Address, error) {
	if tsk.IsEmpty() {
		tsk = minerStateAPI.chain.ChainReader.GetHead()
	}
	st, err := minerStateAPI.chain.ChainReader.GetTipSetState(ctx, tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading state: %v", err)
	}

	var out []address.Address
	err = st.ForEach(func(addr state.ActorKey, act *types.Actor) error {
		out = append(out, addr)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (minerStateAPI *MinerStateAPI) StateMinerPower(ctx context.Context, addr address.Address, tsk block.TipSetKey) (*power.MinerPower, error) {
	if tsk.IsEmpty() {
		tsk = minerStateAPI.chain.ChainReader.GetHead()
	}
	ts, err := minerStateAPI.chain.ChainReader.GetTipSet(tsk)
	if err != nil {
		return nil, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	mp, net, hmp, err := getPower(ctx, minerStateAPI.chain, ts.Blocks()[0].ParentStateRoot, addr)
	if err != nil {
		return nil, err
	}

	return &power.MinerPower{
		MinerPower:  mp,
		TotalPower:  net,
		HasMinPower: hmp,
	}, nil
}

func getPower(ctx context.Context, chain *ChainSubmodule, st cid.Cid, maddr address.Address) (power.Claim, power.Claim, bool, error) {
	store := chain.State.Store(ctx)
	state, err := state.LoadState(ctx, store, st)
	if err != nil {
		return power.Claim{}, power.Claim{}, false, xerrors.Errorf("loading state: %v", err)
	}

	act, found, err := state.GetActor(ctx, power.Address)
	if err != nil {
		return power.Claim{}, power.Claim{}, false, xerrors.Errorf("failed to load power actor: %v", err)
	}
	if !found {
		return power.Claim{}, power.Claim{}, false, xerrors.Errorf("actor not found for %v", power.Address)
	}

	pas, err := power.Load(store, act)
	if err != nil {
		return power.Claim{}, power.Claim{}, false, err
	}

	tpow, err := pas.TotalPower()
	if err != nil {
		return power.Claim{}, power.Claim{}, false, err
	}

	var mpow power.Claim
	var minpow bool
	if maddr != address.Undef {
		var found bool
		mpow, found, err = pas.MinerPower(maddr)
		if err != nil || !found {
			// TODO: return an error when not found?
			return power.Claim{}, power.Claim{}, false, err
		}

		minpow, err = pas.MinerNominalPowerMeetsConsensusMinimum(maddr)
		if err != nil {
			return power.Claim{}, power.Claim{}, false, err
		}
	}

	return mpow, tpow, minpow, nil
}

func (minerStateAPI *MinerStateAPI) StateMinerAvailableBalance(ctx context.Context, maddr address.Address, tsk block.TipSetKey) (big.Int, error) {
	if tsk.IsEmpty() {
		tsk = minerStateAPI.chain.ChainReader.GetHead()
	}
	ts, err := minerStateAPI.chain.ChainReader.GetTipSet(tsk)
	if err != nil {
		return big.Int{}, xerrors.Errorf("loading tipset %s: %v", tsk, err)
	}

	store := minerStateAPI.chain.State.Store(ctx)
	st, err := state.LoadState(ctx, store, ts.Blocks()[0].ParentStateRoot)
	if err != nil {
		return big.Int{}, xerrors.Errorf("loading state: %v", err)
	}

	act, found, err := st.GetActor(ctx, maddr)
	if err != nil {
		return big.Int{}, xerrors.Errorf("failed to load miner actor: %v", err)
	}
	if !found {
		return big.Int{}, xerrors.Errorf("actor not found for %v", power.Address)
	}

	mas, err := miner.Load(store, act)
	if err != nil {
		return big.Int{}, xerrors.Errorf("failed to load miner actor state: %v", err)
	}

	vested, err := mas.VestedFunds(ts.EnsureHeight())
	if err != nil {
		return big.Int{}, err
	}

	abal, err := mas.AvailableBalance(act.Balance)
	if err != nil {
		return big.Int{}, err
	}

	return big.Add(abal, vested), nil
}
