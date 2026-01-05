module github.com/guni1192/zgate/relay

go 1.25.5

require (
	github.com/google/gopacket v1.1.19
	github.com/guni1192/zgate v0.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.58.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/kr/text v0.2.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)

replace github.com/guni1192/zgate => ../
