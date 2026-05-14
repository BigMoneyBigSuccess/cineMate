module github.com/BigMoneyBigSuccess/cineMate/api-gateway

go 1.26.0

require (
	github.com/BigMoneyBigSuccess/cineMate/auth-service v0.1.0
	github.com/BigMoneyBigSuccess/cineMate/collections-service v0.1.0
	github.com/BigMoneyBigSuccess/cineMate/social-service v0.1.0
	github.com/google/uuid v1.6.0
	google.golang.org/grpc v1.79.3
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace (
	github.com/BigMoneyBigSuccess/cineMate/auth-service => ../auth-service
	github.com/BigMoneyBigSuccess/cineMate/collections-service => ../collections-service
	github.com/BigMoneyBigSuccess/cineMate/social-service => ../social-service
)
