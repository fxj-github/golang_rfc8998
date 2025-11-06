package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml"
)

const (
	ca_conf = "./ca.toml"
	ckey_dir      = "./ckey/"
	ca_key_pem  = "ca_key.pem"

	max_req_size_default = 1

	valid_for_default = 90
	valid_for_minimum = 30
)

type CConfig struct {
	Http_ip      string `toml:"http_ip" comment:"RESTFUL address, can be set to 0.0.0.0 after considering security"`
	Http_port    uint16 `toml:"http_port"`

	Key_dir  string     `toml:"key_dir" commented:"true" comment:"private key dir, do not change it"`
	Key_file   string `toml:"key_file" commented:"true"`

	MaxReqSize int    `toml:"max_req_size" comment:"Max Request Size, default 1 MiB"`

	Country string  `toml:"country" comment:"Country, default is CN"`
	Organization string `toml:"organization" comment:"Organization, default is EXAMPLE"`
	OrganizationalUnit string `toml:"organizationalUnit" comment:"OrganizationalUnit, default is www.example.com"`
	CommonName string `toml:"commonName" comment:"CommonName, default is 'EXAMPLE CA'"`

	Valid_for int `toml:"valid_for" comment:"certificate validity period, default 90 days, minimum 30 days."`

	Extra_ca string `toml:"extra_ca" comment:"This is the extra ca file, default empty"`
}

func load_cconfig(file string) (*CConfig, error) {
	cfile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer cfile.Close()

	dec := toml.NewDecoder(cfile)
	dec.Strict(false)
	var conf CConfig
	if err = dec.Decode(&conf); err != nil {
		return nil, err
	}

	if conf.Key_dir == "" {
		conf.Key_dir = ckey_dir
	}

	if conf.Key_file == "" {
		conf.Key_file = ckey_dir + ca_key_pem
	}

	return &conf, nil
}

func save_cconfig(file string, conf *CConfig) error {
	cfile, err := os.Create(file)
	if err != nil {
		return err
	}
	defer cfile.Close()

	enc := toml.NewEncoder(cfile)
	enc.Order(toml.OrderPreserve)
	if err = enc.Encode(conf); err != nil {
		return err
	}
	return nil
}

func file_exist(file string) bool {
	cfile, err := os.Open(file)
	if err != nil {
		return false
	}
	cfile.Close()
	return true
}

func CInit(network_configs string, is_sm2 bool) error {
	if file_exist(ca_conf) {
		return errors.New(fmt.Sprintf("%s already exist! Refuse to overwrite.", ca_conf))
	}
	if file_exist(ckey_dir + ca_key_pem) {
		return errors.New(fmt.Sprintf("%s already exist! Refuse to overwrite.", ckey_dir+ca_key_pem))
	}

	var conf CConfig

	conf.Http_ip = "127.0.0.1"
	conf.Http_port = 10003

	conf.Key_dir = ckey_dir
	conf.Key_file = ckey_dir + ca_key_pem

	conf.MaxReqSize = max_req_size_default

	conf.Country = "CN"
	conf.Organization = "EXAMPLE"
	conf.OrganizationalUnit = "www.example.com"
	conf.CommonName = "EXAMPLE CA"

	conf.Valid_for = valid_for_default

	cnew := strings.Split(network_configs, "/")
	for i, c := range cnew {
		if i == 0 {
			if len(c) > 0 {
				conf.Http_ip = c
			}
		} else if i == 1 {
			if len(c) > 0 {
				port, _ := strconv.ParseInt(c, 10, 32)
				if port <= 0 || port > 65535 {
					return errors.New(fmt.Sprintf("Invalid config string: %s\n", network_configs))
				}
				conf.Http_port = uint16(port)
			}
		} else {
			return errors.New(fmt.Sprintf("Invalid config string: %s\n", network_configs))
		}
	}

	if err := save_cconfig(ca_conf, &conf); err != nil {
		return err
	}
	clog.Info("%s created.\n", ca_conf)

	os.Mkdir(ckey_dir, 0755)
	generate_key(ckey_dir+ca_key_pem, is_sm2)

	return nil
}

func CLoad(upgrade bool) (*CConfig, error) {
	conf, err := load_cconfig(ca_conf)
	if err != nil {
		return nil, err
	}

	var config_changed bool

	if upgrade {
		config_changed = true
	}

	if conf.MaxReqSize < max_req_size_default {
		clog.Warn("max_req_size %d MiB too small, set to default %d MiB\n", conf.MaxReqSize, max_req_size_default)
		conf.MaxReqSize = max_req_size_default
		config_changed = true
	}

	if conf.Valid_for < valid_for_minimum {
		clog.Warn("valid_for %d too small, set to default %d\n", conf.Valid_for, valid_for_default)
		conf.Valid_for = valid_for_default
		config_changed = true
	}

	if config_changed {
		if err := save_cconfig(ca_conf, conf); err != nil {
			return nil, err
		}
		clog.Info("%s updated.\n", ca_conf)
	}

	return conf, nil
}

func CSet(key string, value interface{}) error {
	v, ok := value.(string)
	if !ok {
		return fmt.Errorf("%s's value should be string", key)
	}

	conf, err := load_cconfig(ca_conf)
	if err != nil {
		return err
	}

	var config_changed bool

	if key == "http_ip" {
		if conf.Http_ip != v {
			clog.Info("Change http_ip: %s -> %s\n", conf.Http_ip, v)
			conf.Http_ip = v
			config_changed = true
		}
	} else if key == "http_port" {
		port, _ := strconv.ParseInt(v, 10, 0)
		if port <= 0 || port > 65535 {
			return fmt.Errorf("Invalid http_port: %s", v)
		}
		if conf.Http_port != uint16(port) {
			clog.Info("Change http_port: %d -> %s\n", conf.Http_port, v)
			conf.Http_port = uint16(port)
			config_changed = true
		}
	} else if key == "valid_for" {
		days, _ := strconv.ParseInt(v, 10, 0)
		if int(days) < valid_for_minimum {
			return fmt.Errorf("Invalid valid_for: %s", v)
		}
		if conf.Valid_for != int(days) {
			clog.Info("Change valid_for: %d -> %d\n", conf.Valid_for, int(days))
			conf.Valid_for = int(days)
			config_changed = true
		}
	} else if key == "extra_ca" {
		if conf.Extra_ca != v {
			clog.Info("Change extra_ca: %s -> %s\n", conf.Extra_ca, v)
			conf.Extra_ca = v
			config_changed = true
		}
	} else {
		return fmt.Errorf("Unknown key: %s", key)
	}

	if !config_changed {
		return nil
	}

	if err = save_cconfig(ca_conf, conf); err != nil {
		return err
	}
	clog.Info("%s updated.\n", ca_conf)
	return nil
}
