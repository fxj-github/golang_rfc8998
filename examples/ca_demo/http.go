package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	e_deny         = errors.New("Deny")
	e_deny_revoked = errors.New("Deny as cert revoked")
)

func test(w http.ResponseWriter, r *http.Request, ca *CA) {
	fmt.Fprintf(w, "%s %s %s\n", r.Method, r.URL, r.Proto)
	fmt.Fprintf(w, "Host: %q\n", r.Host)
	for k, v := range r.Header {
		fmt.Fprintf(w, "Header[%q] = %q\n", k, v)
	}

	err := r.ParseMultipartForm(int64(ca.conf.MaxReqSize*1024*1024) * 3)
	if err == nil {
		defer r.MultipartForm.RemoveAll()
	} else if err != http.ErrNotMultipart {
		fmt.Fprintf(w, "%q\n", err)
		return
	}
	if r.MultipartForm != nil {
		for k, v := range r.MultipartForm.Value {
			fmt.Fprintf(w, "MultipartForm_Value[%q] = %q\n", k, v)
		}
		for k, v := range r.MultipartForm.File {
			fmt.Fprintf(w, "MultipartForm_File[%q] = %v\n", k, v)
		}
	}

	for k, v := range r.Form {
		fmt.Fprintf(w, "Form[%q] = %q\n", k, v)
	}
}

func get_ca_cert(w http.ResponseWriter, r *http.Request, ca *CA) error {
	cert, err := ca.get_ca_cert()
	if err != nil {
		return jsonError(w, err)
	}
	return jsonResult(w, string(cert))
}

func get_crl(w http.ResponseWriter, r *http.Request, ca *CA) error {
	cert, err := ca.get_crl()
	if err != nil {
		return jsonError(w, err)
	}
	return jsonResult(w, string(cert))
}

func get_ca_params(w http.ResponseWriter, r *http.Request, ca *CA) error {
	params := &CaParams{Country: ca.conf.Country, Organization: ca.conf.Organization, OrganizationalUnit: ca.conf.OrganizationalUnit}
	b, _ := json.Marshal(&params)
	return jsonResult(w, string(b))
}

func sign(w http.ResponseWriter, r *http.Request, ca *CA) error {
	if err := r.ParseForm(); err != nil {
		return jsonError(w, err)
	}

	var req string
	reqs, ok := r.Form["req"]
	if ok {
		req = reqs[0]
	}
	if req == "" {
		return jsonError(w, errors.New("Missing req"))
	}

	cert, err := ca.sign(req, 0)
	if err != nil {
		return jsonError(w, err)
	}
	return jsonResult(w, cert)
}

func show(w http.ResponseWriter, r *http.Request, ca *CA) error {
	if err := r.ParseForm(); err != nil {
		return jsonError(w, err)
	}

	var req string
	reqs, ok := r.Form["req"]
	if ok {
		req = reqs[0]
	}
	ret, err := ca.Show(req, false)
	if err != nil {
		return jsonError(w, err)
	}
	fmt.Fprintf(w, "%s", ret)
	return nil
}

func get_bundle(w http.ResponseWriter, r *http.Request, ca *CA) error {
	if err := r.ParseForm(); err != nil {
		return jsonError(w, err)
	}

	var req string
	reqs, ok := r.Form["valid_for"]
	if ok {
		req = reqs[0]
	}
	valid_for := 0
	if req != "" {
		n, err := strconv.ParseInt(req, 0, 0)
		if err != nil || int(n) < 0 {
			return jsonError(w, fmt.Errorf("Invalid 'valid_for' format: %v", err))
		}
		valid_for = int(n)
	}

	user_key, client_key, client_csr, client_crt, ca_crt, err := ca.getBundle("w", valid_for)
	if err != nil {
		return jsonError(w, err)
	}

	return build_zip_and_send(w, user_key, client_key, client_csr, client_crt, ca_crt)
}

func build_zip_and_send(w http.ResponseWriter, user_key, client_key, client_csr, client_crt, ca_crt []byte) error {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	header := &zip.FileHeader{ Method: zip.Deflate, Modified: time.Now() }
	header.Name = "bundle/user.key"
	header.SetMode(0600)
	f, err := zw.CreateHeader(header)
	if err != nil {
		return jsonError(w, err)
	}
	if _, err = f.Write(user_key); err != nil {
		return jsonError(w, err)
	}

	header = &zip.FileHeader{ Method: zip.Deflate, Modified: time.Now() }
	header.Name = "bundle/client.key"
	header.SetMode(0600)
	f, err = zw.CreateHeader(header)
	if err != nil {
		return jsonError(w, err)
	}
	if _, err = f.Write(client_key); err != nil {
		return jsonError(w, err)
	}

	header = &zip.FileHeader{ Method: zip.Deflate, Modified: time.Now() }
	header.Name = "bundle/client.csr"
	header.SetMode(0644)
	f, err = zw.CreateHeader(header)
	if err != nil {
		return jsonError(w, err)
	}
	if _, err = f.Write(client_csr); err != nil {
		return jsonError(w, err)
	}

	header = &zip.FileHeader{ Method: zip.Deflate, Modified: time.Now() }
	header.Name = "bundle/client.crt"
	header.SetMode(0644)
	f, err = zw.CreateHeader(header)
	if err != nil {
		return jsonError(w, err)
	}
	if _, err = f.Write(client_crt); err != nil {
		return jsonError(w, err)
	}

	header = &zip.FileHeader{ Method: zip.Deflate, Modified: time.Now() }
	header.Name = "bundle/ca.crt"
	header.SetMode(0644)
	f, err = zw.CreateHeader(header)
	if err != nil {
		return jsonError(w, err)
	}
	if _, err = f.Write(ca_crt); err != nil {
		return jsonError(w, err)
	}

	if err = zw.Close(); err != nil {
		return jsonError(w, err)
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"bundle.zip\"")

	w.Write(buf.Bytes())

	return nil
}

func read_one_file(f *zip.File) ([]byte, error) {
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func update_bundle(w http.ResponseWriter, r *http.Request, ca *CA) error {
	err := r.ParseMultipartForm(int64(ca.conf.MaxReqSize*1024*1024) * 3)
	if err == nil {
		defer r.MultipartForm.RemoveAll()
	} else if err != http.ErrNotMultipart {
		return jsonError(w, err)
	}

	var req string
	reqs, ok := r.Form["req"]
	if ok {
		req = reqs[0]
	}
	if req == "" {
		if r.MultipartForm == nil {
			return jsonError(w, errors.New("Missing req"))
		}

		fhs, ok := r.MultipartForm.File["req"]
		if !ok {
			return jsonError(w, errors.New("Missing req"))
		}
		// This should never happen: see go/src/mime/multipart::ReadForm()
		if len(fhs) < 1 {
			return jsonError(w, errors.New("Invalid req: parse failed"))
		}
		file, err := fhs[0].Open()
		if err != nil {
			return jsonError(w, errors.New("Open req failed"))
		}
		got, _ := io.ReadAll(file)
		file.Close()

		req = string(got)
	}

	var v string
	vs, ok := r.Form["valid_for"]
	if ok {
		v = vs[0]
	}
	valid_for := 0
	if v != "" {
		n, err := strconv.ParseInt(v, 0, 0)
		if err != nil || int(n) < 0 {
			return jsonError(w, fmt.Errorf("Invalid 'valid_for' format: %v", err))
		}
		valid_for = int(n)
	}

	zr, err := zip.NewReader(strings.NewReader(req), int64(len(req)))
	if err != nil {
		return jsonError(w, err)
	}
	user_key := []byte{}
	client_key := []byte{}
	client_csr := []byte{}
	ca_crt := []byte{}
	for i := 0; i < len(zr.File); i++ {
		fi := zr.File[i]
		if strings.HasSuffix(fi.Name, "user.key") {
			user_key, err = read_one_file(fi)
			if err != nil {
				return jsonError(w, err)
			}
		} else if strings.HasSuffix(fi.Name, "client.key") {
			client_key, err = read_one_file(fi)
			if err != nil {
				return jsonError(w, err)
			}
		} else if strings.HasSuffix(fi.Name, "client.csr") {
			client_csr, err = read_one_file(fi)
			if err != nil {
				return jsonError(w, err)
			}
		} else if strings.HasSuffix(fi.Name, "client.crt") {
			// Do nothing
		} else if strings.HasSuffix(fi.Name, "ca.crt") {
			ca_crt, err = read_one_file(fi)
			if err != nil {
				return jsonError(w, err)
			}
		} else {
			return jsonError(w, fmt.Errorf("Unknown file name: %s", fi.Name))
		}
	}

	this_ca_crt, err := ca.get_ca_cert()
	if err != nil {
		return jsonError(w, err)
	}
	if !bytes.Equal(ca_crt, this_ca_crt) {
		clog.Warn("CA cert changed\n")
		ca_crt = this_ca_crt
	}

	client_crt, err := ca.sign(string(client_csr), valid_for)
	if err != nil {
		return jsonError(w, err)
	}

	return build_zip_and_send(w, user_key, client_key, client_csr, []byte(client_crt), ca_crt)
}

type JResult struct {
	Code int    `json:"code"`
	Data string `json:"data"`
}

func jsonError(w http.ResponseWriter, err error) error {
	var e JResult

	if err == nil {
		e.Code = 0
	} else if err == e_deny {
		e.Code = 1
	} else if err == e_deny_revoked {
		e.Code = 2
	} else {
		e.Code = 3
	}

	e.Data = fmt.Sprintf("%v", err)

	b, _ := json.Marshal(&e)

	fmt.Fprintf(w, "%s", string(b))
	return nil
}

func jsonResult(w http.ResponseWriter, result string) error {
	var e JResult

	e.Code = 0
	e.Data = result

	b, _ := json.Marshal(&e)

	fmt.Fprintf(w, "%s", string(b))
	return nil
}

type maxBytesHandler struct {
	h http.Handler
	n int64
}

func (h *maxBytesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, h.n)
	h.h.ServeHTTP(w, r)
}

type http_server struct {
	s *http.Server
}

func new_http_server(ca *CA) *http_server {
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) { test(w, r, ca) })
	http.HandleFunc("/get_ca_cert", func(w http.ResponseWriter, r *http.Request) { get_ca_cert(w, r, ca) })
	http.HandleFunc("/get_crl", func(w http.ResponseWriter, r *http.Request) { get_crl(w, r, ca) })
	http.HandleFunc("/get_ca_params", func(w http.ResponseWriter, r *http.Request) { get_ca_params(w, r, ca) })
	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) { sign(w, r, ca) })
	http.HandleFunc("/show", func(w http.ResponseWriter, r *http.Request) { show(w, r, ca) })
	http.HandleFunc("/get_bundle", func(w http.ResponseWriter, r *http.Request) { get_bundle(w, r, ca) })
	http.HandleFunc("/update_bundle", func(w http.ResponseWriter, r *http.Request) { update_bundle(w, r, ca) })

	clog.Info("Listening on: %s:%d\n", ca.conf.Http_ip, ca.conf.Http_port)

	s := &http.Server{
		Addr: net.JoinHostPort(ca.conf.Http_ip, fmt.Sprintf("%d", ca.conf.Http_port)),
		// Use 3 as application/x-www-form-urlencoded will enlarge 2x on original size at worst case
		Handler: &maxBytesHandler{h: http.DefaultServeMux, n: int64(ca.conf.MaxReqSize*1024*1024) * 3},
	}

	return &http_server{s: s}
}

func (hs *http_server) run() {
	if err := hs.s.ListenAndServe(); err != http.ErrServerClosed {
		clog.Fatal("%v\n", err)
	}
}

func (hs *http_server) close() {
	hs.s.Close()
}
