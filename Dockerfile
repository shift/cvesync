FROM golang

RUN go get github.com/shift/cvesync \
  && cd $GOPATH/src/github.com/shift/cvesync \
  && make install \
  && cd \
  && rm -rf $GOPATH/src
CMD ["/opt/cvesync/bin/cvesync"]
