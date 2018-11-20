// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package walletservice

import (
	"context"
	"encoding/hex"
	"math/big"
	"math/rand"
	"net"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/iotexproject/iotex-core/action"
	"github.com/iotexproject/iotex-core/blockchain"
	"github.com/iotexproject/iotex-core/crypto"
	"github.com/iotexproject/iotex-core/explorer"
	exp "github.com/iotexproject/iotex-core/explorer/idl/explorer"
	"github.com/iotexproject/iotex-core/iotxaddress"
	"github.com/iotexproject/iotex-core/logger"
	"github.com/iotexproject/iotex-core/pkg/enc"
	"github.com/iotexproject/iotex-core/pkg/keypair"
	"github.com/iotexproject/iotex-wallet/pb"
)

var (
	// ErrUnlockRequest indicates the error of unlock request
	ErrUnlockRequest = errors.New("invalid unlock request")
	// ErrCreateTransferRequest indicates the error of create transfer request
	ErrCreateTransferRequest = errors.New("invalid create transfer request")
	// ErrCreateVoteRequest indicates the error of create vote request
	ErrCreateVoteRequest = errors.New("invalid create vote request")
	// ErrAddr indicates the error of address
	ErrAddr = errors.New("invalid address")
	// ErrTransfer indicates the error of transfer
	ErrTransfer = errors.New("invalid transfer")
	// ErrVote indicates the error of vote
	ErrVote = errors.New("invalid vote")
	// ErrExecution indicates the error of execution
	ErrExecution = errors.New("invalid execution")
	// ErrDeposit indicates the error of deposit
	ErrDeposit = errors.New("invalid deposit")
	// ErrServer indicates the error of wallet server
	ErrServer = errors.New("invalid wallet server")
)

// WalletServer implements Wallet Service
type WalletServer struct {
	rpcport             string
	grpcserver          *grpc.Server
	explorerAddr        string
	walletRewardFloor   int
	walletRewardCeiling int
	retryNum            int
	retryInterval       int
	creatorPublicKey    string
	creatorPrivateKey   string
}

// NewWalletServer creates an instance of WalletServer
func NewWalletServer(port string, addr string, walletRewardFloor int, walletRewardCeiling int, retryNum int, retryInterval int, creatorPubKey string, creatorPriKey string) *WalletServer {
	return &WalletServer{
		rpcport:             port,
		explorerAddr:        addr,
		walletRewardFloor:   walletRewardFloor,
		walletRewardCeiling: walletRewardCeiling,
		retryNum:            retryNum,
		retryInterval:       retryInterval,
		creatorPublicKey:    creatorPubKey,
		creatorPrivateKey:   creatorPriKey,
	}
}

// NewWallet creates a new wallet
func (s *WalletServer) NewWallet(ctx context.Context, in *pb.NewWalletRequest) (*pb.NewWalletResponse, error) {
	logger.Debug().Msg("Receive new wallet request")
	var chainIDBytes [4]byte
	enc.MachineEndian.PutUint32(chainIDBytes[:], uint32(in.ChainID))
	addr, err := iotxaddress.NewAddress(iotxaddress.IsTestnet, chainIDBytes[:])
	if err != nil {
		logger.Error().Err(err).Msg("error when creating a new address")
		return nil, errors.Wrap(err, "failed to generate a new iotxaddress")
	}

	// Inject a random transfer from creator to the new address
	client := explorer.NewExplorerProxy("http://" + s.explorerAddr)
	publicKey, err := keypair.DecodePublicKey(s.creatorPublicKey)
	if err != nil {
		logger.Error().Err(err).Msg("error when decoding public key")
		return nil, errors.Wrap(err, "failed to decode creator's public key")
	}
	privateKey, err := keypair.DecodePrivateKey(s.creatorPrivateKey)
	if err != nil {
		logger.Error().Err(err).Msg("error when decoding private key")
		return nil, errors.Wrap(err, "failed to decode creator's private key")
	}
	creatorAddr, err := iotxaddress.GetAddressByPubkey(iotxaddress.IsTestnet, chainIDBytes[:], publicKey)
	if err != nil {
		logger.Error().Err(err).Msg("error when getting address by public key")
		return nil, errors.Wrap(err, "failed to generate creator's address")
	}
	creatorAddr.PrivateKey = privateKey
	addrDetails, err := client.GetAddressDetails(creatorAddr.RawAddress)
	if err != nil {
		logger.Error().Err(err).Msg("error when getting address details")
		return nil, errors.Wrap(err, "failed to get creator's address details")
	}
	nonce := uint64(addrDetails.Nonce) + 1

	if err := injectTransfer(client, creatorAddr, addr, nonce, s.walletRewardFloor, s.walletRewardCeiling, s.retryNum, s.retryInterval); err != nil {
		logger.Error().Err(err).Msg("error when injecting some random token")
		return nil, errors.Wrap(err, "failed to inject a random transfer from creator to the new address")
	}

	logger.Info().Str("address", addr.RawAddress).Msg("a wallet has been created successfully")

	addressPb := &pb.Address{
		PublicKey:  keypair.EncodePublicKey(addr.PublicKey),
		PrivateKey: keypair.EncodePrivateKey(addr.PrivateKey),
		RawAddress: addr.RawAddress,
	}
	return &pb.NewWalletResponse{Address: addressPb}, nil
}

// Unlock unlocks a wallet
func (s *WalletServer) Unlock(ctx context.Context, in *pb.UnlockRequest) (*pb.UnlockResponse, error) {
	logger.Debug().Msg("Receive unlock request")

	if len(in.PrivateKey) == 0 {
		return nil, errors.Wrap(ErrUnlockRequest, "private key is empty")
	}
	privateKey, err := keypair.DecodePrivateKey(in.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode private key")
	}
	publicKey, err := crypto.EC283.NewPubKey(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to derive public key from private key")
	}
	var chainIDBytes [4]byte
	enc.MachineEndian.PutUint32(chainIDBytes[:], uint32(in.ChainID))
	address, err := iotxaddress.GetAddressByPubkey(iotxaddress.IsTestnet, chainIDBytes[:], publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get address from public key")
	}
	addressPb := &pb.Address{
		PublicKey:  keypair.EncodePublicKey(publicKey),
		PrivateKey: in.PrivateKey,
		RawAddress: address.RawAddress,
	}
	return &pb.UnlockResponse{Address: addressPb}, nil
}

// SignTransfer signs a raw transfer
func (s *WalletServer) SignTransfer(ctx context.Context, in *pb.SignTransferRequest) (*pb.SignTransferResponse, error) {
	logger.Debug().Msg("Receive create transfer request")

	senderAddr, err := pbToAddress(in.Address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert protobuf's address message to address")
	}

	transfer, err := pbToRawTransfer(in.Transfer)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert protobuf's transfer message %v to raw transfer", in.Transfer)
	}

	if err := action.Sign(transfer, senderAddr.PrivateKey); err != nil {
		return nil, errors.Wrapf(err, "failed to sign transfer %v", transfer)
	}

	transferPb, err := transferToPb(transfer)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert signed transfer %v to protobuf's transfer message", transfer)
	}
	return &pb.SignTransferResponse{Transfer: transferPb}, nil
}

// SignVote signs a raw vote
func (s *WalletServer) SignVote(ctx context.Context, in *pb.SignVoteRequest) (*pb.SignVoteResponse, error) {
	logger.Debug().Msg("Receive create vote request")

	voterAddr, err := pbToAddress(in.Address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert protobuf's address message to address")
	}

	vote, err := pbToRawVote(in.Vote)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert protobuf's vote message %v to raw vote", in.Vote)
	}

	if err := action.Sign(vote, voterAddr.PrivateKey); err != nil {
		return nil, errors.Wrapf(err, "failed to sign vote %v", vote)
	}

	votePb, err := voteToPb(vote)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert signed vote %v to protobuf's vote message", vote)
	}
	return &pb.SignVoteResponse{Vote: votePb}, nil
}

// SignExecution signs a smart contract
func (s *WalletServer) SignExecution(ctx context.Context, in *pb.SignExecutionRequest) (*pb.SignExecutionResponse, error) {
	logger.Debug().Msg("Receive sign smart contract request")

	executorAddr, err := pbToAddress(in.Address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert protobuf's address message to address")
	}
	execution, err := pbToRawExecution(in.Execution)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert smart contract to execution")
	}
	if err := action.Sign(execution, executorAddr.PrivateKey); err != nil {
		return nil, errors.Wrapf(err, "failed to sign execution %v", execution)
	}

	executionPb, err := executionToPb(execution)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert signed smart contract %v to protobuf's smart contract message", execution)
	}
	return &pb.SignExecutionResponse{Execution: executionPb}, nil
}

// SignCreateDeposit signs a createDeposit
func (s *WalletServer) SignCreateDeposit(ctx context.Context, in *pb.SignCreateDepositRequest) (*pb.SignCreateDepositResponse, error) {
	logger.Debug().Msg("Receive sign create deposit request")

	senderAddr, err := pbToAddress(in.Address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert protobuf's address message to address")
	}

	createDeposit, err := pbToRawCreateDeposit(in.CreateDeposit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert protobuf's createDeposit message %v to raw createDeposit", in.CreateDeposit)
	}

	if err := action.Sign(createDeposit, senderAddr.PrivateKey); err != nil {
		return nil, errors.Wrapf(err, "failed to sign createDeposit %v", createDeposit)
	}

	createDepositPb, err := createDepositToPb(createDeposit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert signed createDeposit %v to protobuf's createDeposit message", createDeposit)
	}
	return &pb.SignCreateDepositResponse{CreateDeposit: createDepositPb}, nil
}

// SignSettleDeposit signs a settleDeposit
func (s *WalletServer) SignSettleDeposit(ctx context.Context, in *pb.SignSettleDepositRequest) (*pb.SignSettleDepositResponse, error) {
	logger.Debug().Msg("Receive sign settle deposit request")

	senderAddr, err := pbToAddress(in.Address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert protobuf's address message to address")
	}

	settleDeposit, err := pbToRawSettleDeposit(in.SettleDeposit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert protobuf's settleDeposit message %v to raw settleDeposit", in.SettleDeposit)
	}

	if err := action.Sign(settleDeposit, senderAddr.PrivateKey); err != nil {
		return nil, errors.Wrapf(err, "failed to sign settleDeposit %v", settleDeposit)
	}

	settleDepositPb, err := settleDepositToPb(settleDeposit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to convert signed settleDeposit %v to protobuf's settleDeposit message", settleDeposit)
	}
	return &pb.SignSettleDepositResponse{SettleDeposit: settleDepositPb}, nil
}

// DecodeAddress decodes a raw address
func (s *WalletServer) DecodeAddress(ctx context.Context, in *pb.DecodeAddressRequest) (*pb.DecodeAddressResponse, error) {
	logger.Debug().Msg("Receive decode address request")

	hash, err := iotxaddress.GetPubkeyHash(in.Address)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid address: %s", in.Address)
	}
	var chainIDBytes [4]byte
	enc.MachineEndian.PutUint32(chainIDBytes[:], uint32(in.ChainID))
	return &pb.DecodeAddressResponse{
		Hash:      hex.EncodeToString(hash),
		IsTestnet: iotxaddress.IsTestnet,
		ChainID:   hex.EncodeToString(chainIDBytes[:]),
	}, nil
}

// Start starts the wallet server
func (s *WalletServer) Start() error {
	if s.rpcport == "" {
		logger.Error().Msg("Wallet service is not configured")
		return errors.Wrap(ErrServer, "rpc port is empty")
	}

	lis, err := net.Listen("tcp", s.rpcport)
	if err != nil {
		logger.Error().Err(err).Msg("Wallet server failed to listen")
		return errors.Wrap(err, "wallet server failed to listen")
	}
	logger.Info().
		Str("addr", lis.Addr().String()).
		Msg("Wallet server is listening")

	s.grpcserver = grpc.NewServer()
	pb.RegisterWalletServiceServer(s.grpcserver, s)
	reflection.Register(s.grpcserver)

	go func() {
		if err := s.grpcserver.Serve(lis); err != nil {
			logger.Fatal().Err(err).Msg("Node failed to serve")
		}
	}()
	return nil
}

// Stop stops the wallet server
func (s *WalletServer) Stop() error {
	s.grpcserver.Stop()
	logger.Info().Msg("Wallet server stops")
	return nil
}

// pbToAddress converts a protobuf's address message to address
func pbToAddress(addressPb *pb.Address) (*iotxaddress.Address, error) {
	publicKey, err := keypair.DecodePublicKey(addressPb.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public key from AddressPb")
	}
	privateKey, err := keypair.DecodePrivateKey(addressPb.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode private key from AddressPb")
	}
	return &iotxaddress.Address{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		RawAddress: addressPb.RawAddress,
	}, nil
}

// pbToRawTransfer converts a protobuf's transfer message to raw transfer
func pbToRawTransfer(transferPb *pb.Transfer) (*action.Transfer, error) {
	payload, err := hex.DecodeString(transferPb.Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert transfer's payload from string to bytes")
	}
	amount, ok := big.NewInt(0).SetString(transferPb.Amount, 10)
	if !ok {
		return nil, errors.New("failed to set string for transfer amount")
	}
	gasPrice, ok := big.NewInt(0).SetString(transferPb.GasPrice, 10)
	if !ok {
		return nil, errors.New("failed to set string for transfer gas price")
	}
	return action.NewTransfer(uint64(transferPb.Nonce), amount, transferPb.Sender, transferPb.Recipient, payload,
		uint64(transferPb.GasLimit), gasPrice)
}

// transferToPb converts a transfer to protobuf's transfer message
func transferToPb(transfer *action.Transfer) (*pb.Transfer, error) {
	if transfer == nil {
		return nil, errors.Wrap(ErrTransfer, "transfer cannot be nil")
	}
	transferPb := &pb.Transfer{
		Version:      int64(transfer.Version()),
		Nonce:        int64(transfer.Nonce()),
		Sender:       transfer.Sender(),
		Recipient:    transfer.Recipient(),
		Payload:      hex.EncodeToString(transfer.Payload()),
		SenderPubKey: keypair.EncodePublicKey(transfer.SenderPublicKey()),
		GasLimit:     int64(transfer.GasLimit()),
		Signature:    hex.EncodeToString(transfer.Signature()),
		IsCoinbase:   transfer.IsCoinbase(),
	}
	if transfer.Amount() != nil && len(transfer.Amount().String()) > 0 {
		transferPb.Amount = transfer.Amount().String()
	}
	if transfer.GasPrice() != nil && len(transfer.GasPrice().String()) > 0 {
		transferPb.GasPrice = transfer.GasPrice().String()
	}

	return transferPb, nil
}

// pbToRawVote converts a protobuf's vote message to raw vote
func pbToRawVote(votePb *pb.Vote) (*action.Vote, error) {
	gasPrice, ok := big.NewInt(0).SetString(votePb.GasPrice, 10)
	if !ok {
		return nil, errors.New("failed to set string for vote gas price")
	}
	return action.NewVote(uint64(votePb.Nonce), votePb.VoterAddress, votePb.VoteeAddress, uint64(votePb.GasLimit), gasPrice)
}

// voteToPb converts a vote to protobuf's vote message
func voteToPb(vote *action.Vote) (*pb.Vote, error) {
	if vote == nil {
		return nil, errors.Wrap(ErrVote, "vote cannot be nil")
	}
	votePb := &pb.Vote{
		Version:      int64(vote.Version()),
		Nonce:        int64(vote.Nonce()),
		Signature:    hex.EncodeToString(vote.Signature()),
		VoterAddress: vote.Voter(),
		VoteeAddress: vote.Votee(),
		SelfPubKey:   keypair.EncodePublicKey(vote.VoterPublicKey()),
		GasLimit:     int64(vote.GasLimit()),
	}
	if vote.GasPrice() != nil && len(vote.GasPrice().String()) > 0 {
		votePb.GasPrice = vote.GasPrice().String()
	}
	return votePb, nil
}

// pbToRawExecution converts a protobuf's smart contract to raw execution
func pbToRawExecution(scPb *pb.Execution) (*action.Execution, error) {
	data, err := hex.DecodeString(scPb.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert execution's data to bytes")
	}
	amount, ok := big.NewInt(0).SetString(scPb.Amount, 10)
	if !ok {
		return nil, errors.New("failed to set string for execution amount")
	}
	gasPrice, ok := big.NewInt(0).SetString(scPb.GasPrice, 10)
	if !ok {
		return nil, errors.New("failed to set string for execution gas price")
	}
	return action.NewExecution(scPb.Executor, scPb.Contract, uint64(scPb.Nonce), amount, uint64(scPb.GasLimit), gasPrice, data)
}

// executionToPb converts an execution to protobuf's smart contract message
func executionToPb(execution *action.Execution) (*pb.Execution, error) {
	if execution == nil {
		return nil, errors.Wrap(ErrExecution, "execution cannot be nil")
	}
	executionPb := &pb.Execution{
		Version:        int64(execution.Version()),
		Nonce:          int64(execution.Nonce()),
		Signature:      hex.EncodeToString(execution.Signature()),
		Executor:       execution.Executor(),
		Contract:       execution.Contract(),
		ExecutorPubKey: keypair.EncodePublicKey(execution.ExecutorPublicKey()),
		GasLimit:       int64(execution.GasLimit()),
		Data:           hex.EncodeToString(execution.Data()),
	}
	if execution.Amount() != nil && len(execution.Amount().String()) > 0 {
		executionPb.Amount = execution.Amount().String()
	}
	if execution.GasPrice() != nil && len(execution.GasPrice().String()) > 0 {
		executionPb.GasPrice = execution.GasPrice().String()
	}
	return executionPb, nil
}

// pbToRawCreateDeposit converts a protobuf's createDeposit to raw createDeposit
func pbToRawCreateDeposit(createDepositPb *pb.CreateDeposit) (*action.CreateDeposit, error) {
	amount, ok := big.NewInt(0).SetString(createDepositPb.Amount, 10)
	if !ok {
		return nil, errors.New("failed to set string for deposit amount")
	}
	gasPrice, ok := big.NewInt(0).SetString(createDepositPb.GasPrice, 10)
	if !ok {
		return nil, errors.New("failed to set string for deposit gas price")
	}
	return action.NewCreateDeposit(uint64(createDepositPb.Nonce), amount, createDepositPb.Sender, createDepositPb.Recipient, uint64(createDepositPb.GasLimit), gasPrice), nil
}

// createDepositToPb converts a createDeposit to protobuf's createDeposit message
func createDepositToPb(createDeposit *action.CreateDeposit) (*pb.CreateDeposit, error) {
	if createDeposit == nil {
		return nil, errors.Wrap(ErrExecution, "deposit cannot be nil")
	}
	createDepositPb := &pb.CreateDeposit{
		Version:      int64(createDeposit.Version()),
		Nonce:        int64(createDeposit.Nonce()),
		Signature:    hex.EncodeToString(createDeposit.Signature()),
		Sender:       createDeposit.Sender(),
		Recipient:    createDeposit.Recipient(),
		SenderPubKey: keypair.EncodePublicKey(createDeposit.SenderPublicKey()),
		GasLimit:     int64(createDeposit.GasLimit()),
	}
	if createDeposit.Amount() != nil && len(createDeposit.Amount().String()) > 0 {
		createDepositPb.Amount = createDeposit.Amount().String()
	}
	if createDeposit.GasPrice() != nil && len(createDeposit.GasPrice().String()) > 0 {
		createDepositPb.GasPrice = createDeposit.GasPrice().String()
	}
	return createDepositPb, nil
}

// pbToRawSettleDeposit converts a protobuf's settleDeposit to raw settleDeposit
func pbToRawSettleDeposit(settleDepositPb *pb.SettleDeposit) (*action.SettleDeposit, error) {
	amount, ok := big.NewInt(0).SetString(settleDepositPb.Amount, 10)
	if !ok {
		return nil, errors.New("failed to set string for deposit amount")
	}
	gasPrice, ok := big.NewInt(0).SetString(settleDepositPb.GasPrice, 10)
	if !ok {
		return nil, errors.New("failed to set string for deposit gas price")
	}
	return action.NewSettleDeposit(uint64(settleDepositPb.Nonce), amount, uint64(settleDepositPb.Index),
		settleDepositPb.Sender, settleDepositPb.Recipient, uint64(settleDepositPb.GasLimit), gasPrice), nil
}

// settleDepositToPb converts a settleDeposit to protobuf's settleDeposit message
func settleDepositToPb(settleDeposit *action.SettleDeposit) (*pb.SettleDeposit, error) {
	if settleDeposit == nil {
		return nil, errors.Wrap(ErrExecution, "deposit cannot be nil")
	}
	settleDepositPb := &pb.SettleDeposit{
		Version:      int64(settleDeposit.Version()),
		Nonce:        int64(settleDeposit.Nonce()),
		Index:        int64(settleDeposit.Index()),
		Signature:    hex.EncodeToString(settleDeposit.Signature()),
		Sender:       settleDeposit.Sender(),
		Recipient:    settleDeposit.Recipient(),
		SenderPubKey: keypair.EncodePublicKey(settleDeposit.SenderPublicKey()),
		GasLimit:     int64(settleDeposit.GasLimit()),
	}
	if settleDeposit.Amount() != nil && len(settleDeposit.Amount().String()) > 0 {
		settleDepositPb.Amount = settleDeposit.Amount().String()
	}
	if settleDeposit.GasPrice() != nil && len(settleDeposit.GasPrice().String()) > 0 {
		settleDepositPb.GasPrice = settleDeposit.GasPrice().String()
	}
	return settleDepositPb, nil
}

// injectTransfer injects a transfer
func injectTransfer(
	c exp.Explorer,
	sender *iotxaddress.Address,
	recipient *iotxaddress.Address,
	nonce uint64,
	walletRewardFloor int,
	walletRewardCeiling int,
	retryNum int,
	retryInterval int,
) error {
	amount := blockchain.ConvertIotxToRau(int64(walletRewardFloor + rand.Intn(walletRewardCeiling-walletRewardFloor+1)))

	transfer, err := createSignedTransfer(sender, recipient, amount, nonce, uint64(1000000), big.NewInt(10), []byte{})
	if err != nil {
		return errors.Wrap(err, "failed to create a signed transfer")
	}

	tsf := transfer.ToJSON()
	request := exp.SendTransferRequest{
		Version:      tsf.Version,
		Nonce:        tsf.Nonce,
		Sender:       tsf.Sender,
		Recipient:    tsf.Recipient,
		Amount:       tsf.Amount,
		SenderPubKey: tsf.SenderPubKey,
		GasLimit:     tsf.GasLimit,
		GasPrice:     tsf.GasPrice,
		Signature:    tsf.Signature,
		Payload:      tsf.Payload,
	}
	for i := 0; i < retryNum; i++ {
		if _, err = c.SendTransfer(request); err == nil {
			break
		}
		time.Sleep(time.Duration(retryInterval) * time.Second)
	}
	if err != nil {
		return errors.Wrapf(err, "failed to send transfer %v", tsf)
	}
	return nil
}

// createSignedTransfer creates and signs a transfer
func createSignedTransfer(
	sender *iotxaddress.Address,
	recipient *iotxaddress.Address,
	amount *big.Int,
	nonce uint64,
	gasLimit uint64,
	gasPrice *big.Int,
	payload []byte,
) (*action.Transfer, error) {
	transfer, err := action.NewTransfer(nonce, amount, sender.RawAddress, recipient.RawAddress, payload, gasLimit, gasPrice)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create raw transfer")
	}
	if err := action.Sign(transfer, sender.PrivateKey); err != nil {
		return nil, errors.Wrapf(err, "failed to sign transfer %v", transfer)
	}
	return transfer, nil
}
