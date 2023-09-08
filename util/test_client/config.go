package main

// Config enumerates the options to enable when composing all of the tests cases to cover while
// running the test client.
type Config struct {

	// 0: no randomization, 1: Randomize, 2: Randomize and Don't Randomize (2 separate tests)
	PortRandomization int `yaml:"port_randomization",json:"port_randomization",toml:"port_randomization"`

	// Which Registrars are enabled
	Registrars EnabledRegistrars `yaml:"registrars",json:"registrars",toml:"registrars"`

	// Which Transports are enabled
	Transports EnabledTransports `yaml:"transports",json:"transports",toml:"transports"`

	NTrials int `yaml:"n_trials",json:"n_trials",toml:"n_trials"`

	// Covert address to use for the tests
	CovertAddress string `yaml:"covert_address",json:"covert_address",toml:"covert_address"`

	// delay between each test
	TestDelay int `yaml:"test_delay",json:"test_delay",toml:"test_delay"`

	// map of generation number to ClientConf path for that generation
	generations map[int]string `yaml:"generations",json:"generations",toml:"generations"`

	// ----------[ Output ]---------- //

	// Log Level
	LogLevel string `yaml:"log_level",json:"log_level",toml:"log_level"`

	// Conjure Log File
	ConjureLogFile string `yaml:"conjure_log_file",json:"conjure_log_file",toml:"conjure_log_file"`

	// Test Runner Log File
	TestRunnerLogFile string `yaml:"test_runner_log_file",json:"test_runner_log_file",toml:"test_runner_log_file"`

	// Output File
	OutputFile string `yaml:"output_file",json:"output_file",toml:"output_file"`
}

type EnabledTransports struct {
	Min    bool `yaml:"min",json:"min",toml:"min"`
	DTLS   bool `yaml:"dtls",json:"dtls",toml:"dtls"`
	Obfs4  bool `yaml:"obfs4",json:"obfs4",toml:"obfs4"`
	Prefix bool `yaml:"prefix",json:"prefix",toml:"prefix"`
}

type EnabledRegistrars struct {
	DNS   bool `yaml:"dns",json:"dns",toml:"dns"`
	API   bool `yaml:"api",json:"api",toml:"api"`
	Decoy bool `yaml:"decoy",json:"decoy",toml:"decoy"`
}

var DefaultConfig = Config{
	PortRandomization: 0,
	Registrars: EnabledRegistrars{
		DNS:   true,
		API:   true,
		Decoy: true,
	},
	Transports: EnabledTransports{
		Min:    true,
		DTLS:   true,
		Obfs4:  true,
		Prefix: true,
	},
	NTrials:        1,
	CovertAddress:  "http://example.com/",
	TestDelay:      750,
	LogLevel:       "info",
	ConjureLogFile: "conjure.log",
	OutputFile:     "output.csv",
}

// ParseConfig parses a config file and returns a Config struct
func ParseConfig(configFile string) (*Config, error) {
	config := DefaultConfig
	if configFile == "" {
		return DefaultConfig, nil
	}
	fileType := filepath.Path(configFile)
	switch fileType {
	case "yaml":
		_, err := yaml.DecodeFile(configFile, &config)
		if err != nil {
			return nil, err
		}

	case "json":
		_, err := json.DecodeFile(configFile, &config)
		if err != nil {
			return nil, err
		}

	case "toml":
		_, err := toml.DecodeFile(configFile, &config)
		if err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("invalid config file type")
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// Validate validates the config ensuring that no contradictory options are set
func (c *Config) Validate() error {
}
