export GOPATH=/C:/Go
go test -v -blockprofile=block.out bp_test.go bp.go bip.go  bprp.go  bulletproofs.go  util.go  vector.go
go test -v -cpuprofile=cpu.out bp_test.go bp.go bip.go  bprp.go  bulletproofs.go  util.go  vector.go
go tool pprof -pdf bulletproofs.test.exe cpu.out > zkrp_cpu.pdf
go tool pprof -pdf bulletproofs.test.exe block.out > zkrp_block.pdf
