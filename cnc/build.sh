gcc cnc.c -o cnc -pthread
export GOROOT=/usr/local/go; export GOPATH=$HOME/Projects/Proj1; export PATH=$GOPATH/bin:$GOROOT/bin:$PATH; go get github.com/go-sql-driver/mysql; go get github.com/mattn/go-shellwords
go build listen.go
rm -rf cnc.c
rm -rf listen.go