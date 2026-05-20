package config

type Config struct {
	Server Server `yaml:"server"`
	Auth   GRPC   `yaml:"auth"`
	Movies GRPC   `yaml:"movies"`
	Social GRPC   `yaml:"social"`
	JWT    JWT    `yaml:"jwt"`
}

type Server struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type GRPC struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type JWT struct {
	SecretFile string `yaml:"secret_file"`
}
