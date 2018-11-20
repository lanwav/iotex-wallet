// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package walletservice

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/iotexproject/iotex-core/config"
	"github.com/iotexproject/iotex-core/crypto"
	"github.com/iotexproject/iotex-core/iotxaddress"
	"github.com/iotexproject/iotex-core/pkg/enc"
	"github.com/iotexproject/iotex-core/pkg/keypair"
	"github.com/iotexproject/iotex-core/server/itx"
	"github.com/iotexproject/iotex-core/testutil"
	"github.com/iotexproject/iotex-wallet/pb"
)

const (
	creatorPubKey = "d01164c3afe47406728d3e17861a3251dcff39e62bdc2b93ccb69a02785a175e195b5605517fd647eb7dd095b3d862dffb087f35eacf10c6859d04a100dbfb7358eeca9d5c37c904"
	creatorPriKey = "d2df3528ff384d41cc9688c354cd301a09f91d95582eb8034a6eff140e7539cb17b53401"
	pubKey1  = "336eb60a5741f585a8e81de64e071327a3b96c15af4af5723598a07b6121e8e813bbd0056ba71ae29c0d64252e913f60afaeb11059908b81ff27cbfa327fd371d35f5ec0cbc01705"
	priKey1  = "925f0c9e4b6f6d92f2961d01aff6204c44d73c0b9d0da188582932d4fcad0d8ee8c66600"
	rawAddr1 = "io1qyqsqqqq8uhx9jtdc2xp5wx7nxyq3xf4c3jmxknzj23d2m"
	pubKey2  = "f8261681ee6e3261eb4aa61123b0edc10bd95c9bb366c6b54348cfef3a055f2f3a3d800277cb15a2c13ac1a44ff1c05191c5729aa62955cb0303e80eeeb24885c8df033405fc5201"
	priKey2  = "6bee2200fa46913e8802a594580f26fa42f75d90ae599cab700bfd22bc6d4b52b34e5301"
	rawAddr2 = "io1qyqsqqqqa3nkp636trcg85x2jfq5rhflcut8ge042xzyfu"

	testChainPath = "./chain.db"
	testTriePath  = "./trie.db"
)

func TestWalletServer_NewWallet(t *testing.T) {
	require := require.New(t)

	testutil.CleanupPath(t, testChainPath)
	testutil.CleanupPath(t, testTriePath)

	cfg, err := newConfig()
	require.NoError(err)
	ctx := context.Background()
	chainID := cfg.Chain.ID

	// create server
	svr, err := itx.NewServer(*cfg)
	require.NoError(err)
	require.Nil(svr.Start(ctx))
	defer func() {
		require.NoError(svr.Stop(ctx))
		testutil.CleanupPath(t, testChainPath)
		testutil.CleanupPath(t, testTriePath)
	}()
	explorerAddr := fmt.Sprintf("127.0.0.1:%d", svr.ChainService(chainID).Explorer().Port())
	s := NewWalletServer(":42124", explorerAddr, 5, 10, 5, 1, creatorPubKey, creatorPriKey)
	s.Start()
	defer s.Stop()

	conn, err := grpc.Dial(":42124", grpc.WithInsecure())
	require.NoError(err)
	defer conn.Close()

	client := pb.NewWalletServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := client.NewWallet(ctx, &pb.NewWalletRequest{ChainID: 1})
	require.NoError(err)

	publicKey, err := keypair.DecodePublicKey(r.Address.PublicKey)
	require.NoError(err)
	require.Equal(72, len(publicKey))
	privateKey, err := keypair.DecodePrivateKey(r.Address.PrivateKey)
	require.NoError(err)
	require.Equal(36, len(privateKey))

	// Wait until the injected transfer for the new address gets into the action pool
	require.NoError(testutil.WaitUntil(100*time.Millisecond, 2*time.Second, func() (bool, error) {
		actions := svr.ChainService(chainID).ActionPool().PickActs()
		return len(actions) == 1, nil
	}))
}

func TestWalletServer_Unlock(t *testing.T) {
	require := require.New(t)

	s := NewWalletServer(":42124", "127.0.0.1:14004", 5, 10, 5, 1, creatorPubKey, creatorPriKey)
	s.Start()
	defer s.Stop()

	conn, err := grpc.Dial(":42124", grpc.WithInsecure())
	require.NoError(err)
	defer conn.Close()

	client := pb.NewWalletServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := client.Unlock(ctx, &pb.UnlockRequest{PrivateKey: priKey1, ChainID: 1})
	require.NoError(err)

	require.Equal(pubKey1, r.Address.PublicKey)
	require.Equal(rawAddr1, r.Address.RawAddress)

	r, err = client.Unlock(ctx, &pb.UnlockRequest{PrivateKey: priKey2, ChainID: 2})
	require.NoError(err)

	require.Equal(pubKey2, r.Address.PublicKey)
	require.NotEqual(rawAddr2, r.Address.RawAddress)
}

func TestWalletServer_SignTransfer(t *testing.T) {
	require := require.New(t)

	s := NewWalletServer(":42124", "127.0.0.1:14004", 5, 10, 5, 1, creatorPubKey, creatorPriKey)
	s.Start()
	defer s.Stop()

	conn, err := grpc.Dial(":42124", grpc.WithInsecure())
	require.NoError(err)
	defer conn.Close()

	client := pb.NewWalletServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addressPb := &pb.Address{
		PublicKey:  pubKey1,
		PrivateKey: priKey1,
		RawAddress: rawAddr1,
	}

	rawTransferPb := &pb.Transfer{
		Nonce:     1,
		Amount:    "1",
		Sender:    rawAddr1,
		Recipient: rawAddr2,
		GasLimit:  1000000,
		GasPrice:  "10",
	}

	request := &pb.SignTransferRequest{
		Address:  addressPb,
		Transfer: rawTransferPb,
	}

	response, err := client.SignTransfer(ctx, request)
	require.NoError(err)

	require.NotNil(response.Transfer.Signature)
}

func TestWalletServer_SignVote(t *testing.T) {
	require := require.New(t)

	s := NewWalletServer(":42124", "127.0.0.1:14004", 5, 10, 5, 1, creatorPubKey, creatorPriKey)
	s.Start()
	defer s.Stop()

	conn, err := grpc.Dial(":42124", grpc.WithInsecure())
	require.NoError(err)
	defer conn.Close()

	client := pb.NewWalletServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addressPb := &pb.Address{
		PublicKey:  pubKey2,
		PrivateKey: priKey2,
		RawAddress: rawAddr2,
	}

	rawVotePb := &pb.Vote{
		Nonce:        2,
		VoterAddress: rawAddr2,
		VoteeAddress: rawAddr2,
		GasLimit:     1000000,
		GasPrice:     "10",
	}

	request := &pb.SignVoteRequest{
		Address: addressPb,
		Vote:    rawVotePb,
	}

	response, err := client.SignVote(ctx, request)
	require.NoError(err)

	require.NotNil(response.Vote.Signature)
}

func TestWalletServer_SignExecution(t *testing.T) {
	require := require.New(t)

	s := NewWalletServer(":42124", "127.0.0.1:14004", 5, 10, 5, 1, creatorPubKey, creatorPriKey)
	s.Start()
	defer s.Stop()

	conn, err := grpc.Dial(":42124", grpc.WithInsecure())
	require.NoError(err)
	defer conn.Close()

	client := pb.NewWalletServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addressPb := &pb.Address{
		PublicKey:  pubKey1,
		PrivateKey: priKey1,
		RawAddress: rawAddr1,
	}

	rawExecutionPb := &pb.Execution{
		Nonce:    3,
		Amount:   "3",
		Executor: rawAddr1,
		Contract: "",
		GasLimit: 1000000,
		GasPrice: "10",
	}

	request := &pb.SignExecutionRequest{
		Address:   addressPb,
		Execution: rawExecutionPb,
	}

	response, err := client.SignExecution(ctx, request)
	require.NoError(err)

	require.NotNil(response.Execution.Signature)
}

func TestWalletServer_SignCreateDeposit(t *testing.T) {
	require := require.New(t)

	s := NewWalletServer(":42124", "127.0.0.1:14004", 5, 10, 5, 1, creatorPubKey, creatorPriKey)
	s.Start()
	defer s.Stop()

	conn, err := grpc.Dial(":42124", grpc.WithInsecure())
	require.NoError(err)
	defer conn.Close()

	client := pb.NewWalletServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addressPb := &pb.Address{
		PublicKey:  pubKey2,
		PrivateKey: priKey2,
		RawAddress: rawAddr2,
	}

	var chainIDBytes [4]byte
	enc.MachineEndian.PutUint32(chainIDBytes[:], uint32(2))
	pubkey, err := keypair.DecodePublicKey(pubKey2)
	require.NoError(err)
	addr, err := iotxaddress.GetAddressByPubkey(iotxaddress.IsTestnet, chainIDBytes[:], pubkey)

	rawCreateDepositPb := &pb.CreateDeposit{
		Nonce:     4,
		Amount:    "4",
		Sender:    rawAddr2,
		Recipient: addr.RawAddress,
		GasLimit:  1000000,
		GasPrice:  "10",
	}

	request := &pb.SignCreateDepositRequest{
		Address:       addressPb,
		CreateDeposit: rawCreateDepositPb,
	}

	response, err := client.SignCreateDeposit(ctx, request)
	require.NoError(err)

	require.NotNil(response.CreateDeposit.Signature)
}

func TestWalletServer_SignSettleDeposit(t *testing.T) {
	require := require.New(t)

	s := NewWalletServer(":42124", "127.0.0.1:14004", 5, 10, 5, 1, creatorPubKey, creatorPriKey)
	s.Start()
	defer s.Stop()

	conn, err := grpc.Dial(":42124", grpc.WithInsecure())
	require.NoError(err)
	defer conn.Close()

	client := pb.NewWalletServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	addressPb := &pb.Address{
		PublicKey:  pubKey1,
		PrivateKey: priKey1,
		RawAddress: rawAddr1,
	}

	var chainIDBytes [4]byte
	enc.MachineEndian.PutUint32(chainIDBytes[:], uint32(2))
	pubkey, err := keypair.DecodePublicKey(pubKey1)
	require.NoError(err)
	addr, err := iotxaddress.GetAddressByPubkey(iotxaddress.IsTestnet, chainIDBytes[:], pubkey)

	rawSettleDepositPb := &pb.SettleDeposit{
		Nonce:     5,
		Amount:    "5",
		Index:     0,
		Sender:    rawAddr1,
		Recipient: addr.RawAddress,
		GasLimit:  1000000,
		GasPrice:  "10",
	}

	request := &pb.SignSettleDepositRequest{
		Address:       addressPb,
		SettleDeposit: rawSettleDepositPb,
	}

	response, err := client.SignSettleDeposit(ctx, request)
	require.NoError(err)

	require.NotNil(response.SettleDeposit.Signature)
}

func newConfig() (*config.Config, error) {
	cfg := config.Default
	cfg.NodeType = config.DelegateType
	cfg.Consensus.Scheme = config.NOOPScheme
	cfg.Chain.ChainDBPath = testChainPath
	cfg.Chain.TrieDBPath = testTriePath
	cfg.Chain.GenesisActionsPath = "./testnet_actions.yaml"

	pk, sk, err := crypto.EC283.NewKeyPair()
	if err != nil {
		return nil, err
	}
	cfg.Chain.ProducerPubKey = keypair.EncodePublicKey(pk)
	cfg.Chain.ProducerPrivKey = keypair.EncodePrivateKey(sk)
	cfg.Network.Port = 0
	cfg.Network.PeerMaintainerInterval = 100 * time.Millisecond
	cfg.Explorer.Enabled = true
	cfg.Explorer.Port = 0
	return &cfg, nil
}
