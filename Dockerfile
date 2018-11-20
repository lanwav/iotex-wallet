FROM golang:1.10.2-stretch

RUN apt-get install -y --no-install-recommends make && \
    mkdir -p $GOPATH/src/github.com/iotexproject/iotex-wallet/

COPY ./ $GOPATH/src/github.com/iotexproject/iotex-wallet/

ARG SKIP_DEP=false

RUN if [ "$SKIP_DEP" != true ] ; \
    then \
        cd $GOPATH/src/github.com/iotexproject/iotex-wallet/ && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && \
        dep ensure ; \
    fi

RUN cd $GOPATH/src/github.com/iotexproject/iotex-wallet/ && \
    make clean build && \
    ln -s $GOPATH/src/github.com/iotexproject/iotex-wallet/bin/server /usr/local/bin/iotex-wallet-server && \
    cp $GOPATH/src/github.com/iotexproject/iotex-wallet/vendor/github.com/iotexproject/iotex-core/crypto/lib/libsect283k1_ubuntu.so /usr/lib/ && \
    cp $GOPATH/src/github.com/iotexproject/iotex-wallet/vendor/github.com/iotexproject/iotex-core/crypto/lib/blslib/libtblsmnt_ubuntu.so /usr/lib/

CMD ["iotex-wallet-server"]
