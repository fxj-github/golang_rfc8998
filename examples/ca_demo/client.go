package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ca_client struct {
	client  *http.Client
	address string
}

func new_ca_client(network_configs string) (*ca_client, error) {
	http_ip := ""
	http_port := uint16(0)

	cnew := strings.Split(network_configs, ",")
	for i, c := range cnew {
		if i == 0 {
			if len(c) > 0 {
				http_ip = c
			}
		} else if i == 1 {
			if len(c) > 0 {
				port, _ := strconv.ParseInt(c, 10, 32)
				if port <= 0 || port > 65535 {
					return nil, fmt.Errorf("Invalid config string: %s", network_configs)
				}
				http_port = uint16(port)
			}
		} else {
			return nil, fmt.Errorf("Invalid config string: %s", network_configs)
		}
	}

	if len(http_ip) == 0 || http_port == 0 {
		return nil, fmt.Errorf("Invalid config string: %s", network_configs)
	}

	return &ca_client{client: &http.Client{}, address: net.JoinHostPort(http_ip, fmt.Sprintf("%d", http_port))}, nil
}

func (c *ca_client) get_response(cancel context.CancelFunc, req *http.Request, max_response_len int) ([]byte, string, error) {
	type response struct {
		data []byte
		last_url string
		err error
	}

	ch := make(chan response)

	go func() {
		var r response
		defer func() { ch <- r }()

		resp, err := c.client.Do(req)
		if err != nil {
			r.err = err
			return
		}
		defer resp.Body.Close()

		// FIXME: alloc it dynamically
		buf := make([]byte, max_response_len)
		n, _ := io.ReadFull(resp.Body, buf)
		if n > 0 {
			r.data = buf[:n]
			r.last_url = resp.Request.URL.String()
		} else {
			r.err = errors.New("Empty response")
		}
	}()

	var r response
	var done bool

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	select {
	case r = <- ch:
		done = true
	case <- timer.C:
	}

	cancel()

	if !done {
		r = <- ch
	}

	if r.err != nil {
		return nil, "", r.err
	}

	return r.data, r.last_url, nil
}

func (c *ca_client) get_ca_cert_or_crl(api string) ([]byte, error) {
	var address string
	if strings.HasPrefix(c.address, "http://") || strings.HasPrefix(c.address, "https://") {
		address = c.address+"/"+api
	} else {
		address = "http://"+c.address+"/"+api
	}

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		cancel()
		return nil, err
	}

	data, _, err := c.get_response(cancel, req, 4000000)
	if err != nil {
		return nil, err
	}

	var result JResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		clog.Debug("data: %s", data)
		return nil, err
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("code: %d data: %s", result.Code, result.Data)
	}

	return []byte(result.Data), nil
}

func (c *ca_client) get_ca_params() (*CaParams, error) {
	var address string
	if strings.HasPrefix(c.address, "http://") || strings.HasPrefix(c.address, "https://") {
		address = c.address+"/get_ca_params"
	} else {
		address = "http://"+c.address+"/get_ca_params"
	}

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		cancel()
		return nil, err
	}

	data, _, err := c.get_response(cancel, req, 8000)
	if err != nil {
		return nil, err
	}

	var result JResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		clog.Debug("data: %s", data)
		return nil, err
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("code: %d data: %s", result.Code, result.Data)
	}

	var params CaParams
	err = json.Unmarshal([]byte(result.Data), &params)
	if err != nil {
		return nil, err
	}
	return &params, nil
}

func (c *ca_client) sign(csr []byte) ([]byte, error) {
	var old_url string
	if strings.HasPrefix(c.address, "http://") || strings.HasPrefix(c.address, "https://") {
		old_url = c.address+"/sign"
	} else {
		old_url = "http://"+c.address+"/sign"
	}
	retried := false

	reqdata := make(url.Values)
	reqdata.Set("req", string(csr))

retry:
	ctx, cancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(ctx, "POST", old_url, strings.NewReader(reqdata.Encode()))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	data, new_url, err := c.get_response(cancel, req, 8000)
	if err != nil {
		return nil, err
	}

	var result JResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		clog.Debug("data: %s", data)
		return nil, err
	}
	if result.Code != 0 {
		clog.Debug("New url: %s\n", new_url)
		if new_url != old_url && !retried {
			old_url = new_url
			retried = true
			goto retry
		}
		return nil, fmt.Errorf("code: %d data: %s", result.Code, result.Data)
	}

	return []byte(result.Data), nil
}
