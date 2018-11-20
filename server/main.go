// Copyright (c) 2018 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

// Usage:
//   make build
//   ./bin/server -port="target_port_for_grpc_connection"
//

package main

import (
	"flag"

	"github.com/iotexproject/iotex-core/logger"
	"github.com/iotexproject/iotex-wallet/walletservice"
)

func main() {
	// target port for grpc connection. Default is ":42124"
	var port string
	// target address for explorer connection. Default is "127.0.0.1:14004"
	var explorerAddr string
	// lower bound of reward when creating a new wallet. Default is 5
	var walletRewardFloor int
	// upper bound of reward when creating a new wallet. Default is 10
	var walletRewardCeiling int
	// maximum number of rpc retries. Default is 5
	var retryNum int
	// sleeping period between two consecutive rpc retries in seconds. Default is 1
	var retryInterval int
	// public key of creator who can send token rewards to the newly created wallet
	var creatorPublicKey string
	// private key of creator who can send token rewards to the newly created wallet
	var creatorPrivateKey string

	flag.StringVar(&port, "port", ":42124", "target port for grpc connection")
	flag.StringVar(&explorerAddr, "exp-addr", "127.0.0.1:14004", "target ip:port for explorer connection")
	flag.IntVar(&walletRewardFloor, "reward-floor", 5, "lower bound of reward when creating a new wallet")
	flag.IntVar(&walletRewardCeiling, "reward-ceiling", 10, "upper bound of reward when creating a new wallet")
	flag.IntVar(&retryNum, "retry-num", 5, "maximum number of rpc retries")
	flag.IntVar(&retryInterval, "retry-interval", 1, "sleep interval between two consecutive rpc retries in seconds")
	flag.StringVar(&creatorPublicKey, "creator-pubkey", "",
		"public key of creator who can send token rewards to the newly created wallet")
	flag.StringVar(&creatorPrivateKey, "creator-prikey", "",
		"private key of creator who can send token rewards to the newly created wallet")
	flag.Parse()

	server := walletservice.NewWalletServer(port, explorerAddr, walletRewardFloor, walletRewardCeiling, retryNum, retryInterval, creatorPublicKey, creatorPrivateKey)
	logger.Info().Msg("Starting wallet server")
	server.Start()
	defer server.Stop()

	select {}
}
