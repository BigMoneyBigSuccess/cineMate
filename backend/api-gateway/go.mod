module github.com/BigMoneyBigSuccess/cineMate/api-gateway

go 1.26.1

require (
	github.com/BigMoneyBigSuccess/cineMate/clients v0.1.0
	github.com/BigMoneyBigSuccess/cineMate/logger v0.1.0
	github.com/BigMoneyBigSuccess/cineMate/proto v0.1.0
	google.golang.org/grpc v1.79.3
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace (
	github.com/BigMoneyBigSuccess/cineMate/clients => ../clients
	github.com/BigMoneyBigSuccess/cineMate/logger => ../logger
	github.com/BigMoneyBigSuccess/cineMate/proto => ../proto
)
