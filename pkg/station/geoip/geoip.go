package geoip

import (
	"errors"
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// Database provides the minimal useful interface for looking up relevant information so we
// aren't tied tp the types / interface of a specific GeoIP library
type Database interface {
	ASN(ip net.IP) (uint, error)
	CC(ip net.IP) (string, error)
}

var (
	// ErrMissingDB indicates that one or more of the utility databases was not provided. The wrapped
	// error message should indicate which database was missing.
	ErrMissingDB = errors.New("missing one or more geoip DBs")
)

// DBConfig contains options used for GeoIP lookup - including paths to database files
type DBConfig struct {
	CCDBPath  string `toml:"geoip_cc_db_path"`
	ASNDBPath string `toml:"geoip_asn_db_path"`
}

// New returns a database given a config. If the provided config is nil, the Empty Database will
// be returned.
func New(conf *DBConfig) (Database, error) {

	// If no config is provided or the config provided contains no DB paths return the empty db.
	if conf == nil {
		return &EmptyDatabase{}, fmt.Errorf("%w: no config", ErrMissingDB)
	} else if conf.ASNDBPath == "" && conf.CCDBPath == "" {
		return &EmptyDatabase{}, fmt.Errorf("%w: no asn or cc db files", ErrMissingDB)
	}

	db := &maxMindDatabase{DBConfig: conf}

	err := db.init()
	if errors.Is(err, ErrMissingDB) {
		return db, err
	} else if err != nil {
		return nil, err
	}

	return db, nil
}

// maxMindDatabase provides the GeoIP functionality that we need using the MaxMind GeoIP service
type maxMindDatabase struct {
	*DBConfig

	asnReader *geoip2.Reader
	ccReader  *geoip2.Reader
}

// ASN returns the Autonomous System Number (ASN) associated with the provided IP.
func (mmdb *maxMindDatabase) init() error {
	var err error

	if mmdb.ASNDBPath != "" {
		mmdb.asnReader, err = geoip2.Open(mmdb.DBConfig.ASNDBPath)
		if err != nil {
			return err
		}
	}

	if mmdb.CCDBPath != "" {
		mmdb.ccReader, err = geoip2.Open(mmdb.DBConfig.CCDBPath)
		if err != nil {
			return err
		}
	}

	if mmdb.ccReader == nil && mmdb.asnReader != nil {
		return fmt.Errorf("%w: no cc db file", ErrMissingDB)
	} else if mmdb.ccReader != nil && mmdb.asnReader == nil {
		return fmt.Errorf("%w: no asn db file", ErrMissingDB)
	}

	return nil
}

// ASN returns the Autonomous System Number (ASN) associated with the provided IP.
func (mmdb *maxMindDatabase) ASN(ipAddress net.IP) (uint, error) {
	if mmdb == nil || mmdb.asnReader == nil {
		return 0, nil
	}

	record, err := mmdb.asnReader.ASN(ipAddress)
	if err != nil {
		return 0, err
	}

	return record.AutonomousSystemNumber, nil
}

// CC returns the ISO country code associated with the provided IP.
func (mmdb *maxMindDatabase) CC(ipAddress net.IP) (string, error) {
	if mmdb == nil || mmdb.ccReader == nil {
		return "", nil
	}

	record, err := mmdb.ccReader.Country(ipAddress)
	if err != nil {
		return "", err
	}

	return record.Country.IsoCode, nil
}
