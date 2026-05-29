module github.com/BigMoneyBigSuccess/cineMate/auth-service

go 1.26.1

require (
	github.com/goccy/go-yaml v1.19.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	golang.org/x/crypto v0.49.0
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/BigMoneyBigSuccess/cineMate/clients v0.1.0
	github.com/BigMoneyBigSuccess/cineMate/logger v0.1.0
	github.com/BigMoneyBigSuccess/cineMate/proto v0.1.0
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.12.3
	google.golang.org/grpc v1.79.3
)

require google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect

replace (
	github.com/BigMoneyBigSuccess/cineMate/clients => ../clients
	github.com/BigMoneyBigSuccess/cineMate/logger => ../logger
	github.com/BigMoneyBigSuccess/cineMate/proto => ../proto
)
