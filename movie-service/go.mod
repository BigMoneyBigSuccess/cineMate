<<<<<<< HEAD
module github.com/BigMoneyBigSuccess/cineMate/movie-service
=======
module movie_service
>>>>>>> 26ab2e2 (took out environment variables into .env file & added syncer for fetching films from open api service & took out proto files from movie-service, now they will lie in shared directory)

go 1.26.1

require (
	github.com/BigMoneyBigSuccess/cineMate/proto v0.1.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.9.2
	github.com/redis/go-redis/v9 v9.5.1
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	proto v0.0.0
)

<<<<<<< HEAD
replace github.com/BigMoneyBigSuccess/cineMate/proto => ../proto
=======
replace proto => ../proto
>>>>>>> 26ab2e2 (took out environment variables into .env file & added syncer for fetching films from open api service & took out proto files from movie-service, now they will lie in shared directory)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
)
