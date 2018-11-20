# iotex-wallet

Wallet Service for [IoTeX blockchain](https://github.com/iotexproject/iotex-core).

## Minimum requirements

| Components | Version | Description |
|----------|-------------|-------------|
|[Golang](https://golang.org) | >= 1.10.2 | The Go Programming Language |

### Setup Dev Environment
```
mkdir -p ~/go/src/github.com/iotexproject
cd ~/go/src/github.com/iotexproject
git clone git@github.com:iotexproject/iotex-wallet.git
cd iotex-wallet
```

Install Go dependency management tool from [golang dep](https://github.com/golang/dep) first and then

```dep ensure --vendor-only```

```make fmt; make build```

Note: If your Dev Environment is in Ubuntu, you need to export the following Path:

LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$GOPATH/src/github.com/iotexproject/iotex-wallet/vendor/github.com/iotexproject/iotex-core/crypto/lib:$GOPATH/src/github.com/iotexproject/iotex-wallet/vendor/github.com/iotexproject/iotex-core/crypto/lib/blslib

### Run unit tests
```make test```

### Run wallet server with default configurations
```make run``` to start wallet server

### Run wallet server with customized configurations
`./bin/server`

You can use command line flags to customize the wallet server.

```
-port=target_port_for_frontend_grpc_connection
-exp-addr=target_ip:port_for_backend_explorer_connection
-reward-floor=lowerbound_of_token_reward_when_creating_a_new_wallet
-reward-ceiling=upperbound_of_token_reward_when_creating_a_new_wallet
-retry-num=maximum_number_of_rpc_retries
-retry-interval=sleep_interval_between_two_consecutive_rpc_retries_in_seconds
-creator-pubkey=public_key_of_creator_who_can_send_token_rewards_to_the_newly_created_wallet
-creator-prikey=private_key_of_creator_who_can_send_token_rewards_to_the_newly_created_wallet
```

Default flag values:
* port=:42124
* exp-addr="127.0.0.1:14004"
* reward-floor=5
* reward-ceiling=10
* retry-num=5
* retry-interval=1
* creator-pubkey=""
* creator-prikey=""

Note: Since both creator-pubkey and creator-prikey are not set by default, you may have to manually configure them using an existing account with sufficient balance of EIOTX.

### Deploy w/ Docker Image
#### Please first install Docker: `https://docs.docker.com/install/`

You may want to modify the last line of Dockerfile in the pattern of ```CMD ["iotex-wallet-server", "param1", "param2"]``` to preset configurations of wallet server before building a docker.

To build a docker image,

```make docker```

Add `SKIP_DEP=true` to skip re-installing dependencies via `dep`.

To run a docker image,

```docker run $USER/iotex-wallet-go:latest```
