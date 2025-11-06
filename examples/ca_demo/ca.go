package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

const (
	ca_db = "./ca.db"
)

type CaParams struct {
	// C
	Country            string `json:"country"`
	// O
	Organization       string `json:"organization"`
	// OU
	OrganizationalUnit string `json:"organizationalUnit"`
	// ST
	Province           string `json:"province"`
	// L
	Locality           []string `json:"locality"`
	// T: 2.5.4.12
	Title              string `json:"title"`
	// CN
	CommonName         string `json:"commonName"`
}

var (
	// 25 years
	validForCA = 25

	certUpdate = 30

	// 30 days
	crlNextUpdate = 30
	crlUpdate     = 7
)

type CA struct {
	key  *ecdsa.PrivateKey
	db   *sql.DB
	conf *CConfig
}

func NewCA(conf *CConfig) (*CA, error) {
	key, err := LoadPrivKey(conf.Key_file)
	if err != nil {
		return nil, err
	}
	db, err := init_db(key, conf)
	if err != nil {
		return nil, err
	}
	return &CA{key: key, db: db, conf: conf}, nil
}

func NewCA_DB() (*CA, error) {
	db, err := open_db()
	if err != nil {
		return nil, err
	}
	return &CA{db: db}, nil
}

func (ca *CA) CloseDB() {
	ca.db.Close()
}

func get_serial_number(nr_bits uint) (*big.Int, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), nr_bits))
	if err != nil {
		return nil, err
	}
	// make sure ORDER BY works...
	serialNumber.Add(serialNumber, new(big.Int).Lsh(big.NewInt(1), nr_bits))
	return serialNumber, nil
}

func create_ca_certificate(priv *ecdsa.PrivateKey, conf *CConfig) ([]byte, error) {
	serialNumber, err := get_serial_number(124)
	if err != nil {
		return nil, err
	}

	keyUsage := x509.KeyUsageDigitalSignature

	notBefore := time.Now().AddDate(0, 0, -1)
	notAfter := notBefore.AddDate(validForCA, 0, 0)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{conf.Country},
			Organization:       []string{conf.Organization},
			OrganizationalUnit: []string{conf.OrganizationalUnit},
			CommonName:         conf.CommonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign
	template.KeyUsage |= x509.KeyUsageCRLSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func bytes_to_hex_string(data []byte) string {
	return hex.EncodeToString(data)
}

func is_serial_number(data string) bool {
	l := len(data)
	if l <= 0 || l > 32 {
		return false
	}
	if _, err := hex.DecodeString(data); err != nil {
		return false
	}
	return true
}

func is_ski(data string) bool {
	l := len(data)
	if l != 40 {
		return false
	}
	if _, err := hex.DecodeString(data); err != nil {
		return false
	}
	return true
}

func open_db() (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_txlock=immediate&_busy_timeout=%d", ca_db, 5000)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func init_db(priv *ecdsa.PrivateKey, conf *CConfig) (*sql.DB, error) {
	db, err := open_db()
	if err != nil {
		return nil, err
	}

	stmt := `
	PRAGMA journal_mode=WAL;
	CREATE TABLE IF NOT EXISTS certs(
		serial TEXT PRIMARY KEY,
		name TEXT,
		ski TEXT,
		is_ca BOOL,
		begin TEXT,
		end TEXT,
		status TEXT,
		revoked_time TEXT,
		cert BLOB
	);
	CREATE INDEX IF NOT EXISTS ski_index ON certs (ski);
	CREATE INDEX IF NOT EXISTS isca_index ON certs (is_ca);
	CREATE INDEX IF NOT EXISTS status_index ON certs (status);
	CREATE TABLE IF NOT EXISTS revokedlist(
		number TEXT PRIMARY KEY,
		this_update TEXT,
		next_update TEXT,
		crl BLOB
	);
	CREATE TABLE IF NOT EXISTS config(
		key TEXT PRIMARY KEY,
		value TEXT
	);
	`
	if _, err = db.Exec(stmt); err != nil {
		db.Close()
		return nil, err
	}

	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, err
	}

	var serial string
	stmt = fmt.Sprintf("SELECT serial FROM certs ORDER BY serial DESC LIMIT 1;")
	err = tx.QueryRow(stmt).Scan(&serial)
	if err != nil && err != sql.ErrNoRows {
		goto err_close
	}
	if err == sql.ErrNoRows {
		var ca_cert_bytes []byte
		ca_cert_bytes, err = create_ca_certificate(priv, conf)
		if err != nil {
			goto err_close
		}

		ca_cert, _ := load_cert(ca_cert_bytes)

		clog.Info("serial: %s\n", bytes_to_hex_string(ca_cert.SerialNumber.Bytes()))
		clog.Info("cname: %s\n", ca_cert.Subject.CommonName)
		clog.Info("begin: %s\n", ca_cert.NotBefore.Format(time.RFC3339))
		clog.Info("end: %s\n", ca_cert.NotAfter.Format(time.RFC3339))
		clog.Info("ski: %s\n", bytes_to_hex_string(ca_cert.SubjectKeyId))

		var sqlstmt *sql.Stmt
		if sqlstmt, err = tx.Prepare("INSERT INTO certs(serial,name,ski,is_ca,begin,end,status,cert) VALUES(?,?,?,?,?,?,?,?)"); err != nil {
			goto err_close
		}
		defer sqlstmt.Close()
		if _, err = sqlstmt.Exec(bytes_to_hex_string(ca_cert.SerialNumber.Bytes()),
			ca_cert.Subject.CommonName,
			bytes_to_hex_string(ca_cert.SubjectKeyId),
			ca_cert.IsCA,
			ca_cert.NotBefore.Format(time.RFC3339),
			ca_cert.NotAfter.Format(time.RFC3339),
			"V",
			ca_cert_bytes); err != nil {
			goto err_close
		}

		stmt = fmt.Sprintf("INSERT INTO config(key,value) VALUES('enable_sign','yes'),('has_new_revoked_certs','no')")
		if _, err = tx.Exec(stmt); err != nil {
			goto err_close
		}
	}
	tx.Commit()
	return db, nil
err_close:
	tx.Rollback()
	db.Close()
	return nil, err
}

func (ca *CA) Run() {
	http_server := new_http_server(ca)
	go http_server.run()

	signal.Ignore(syscall.SIGHUP)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	clog.Info("Receive signal: %v, exiting ...\n", <-sig)

	clog.Info("Stop HTTP server ...\n")
	http_server.close()

	clog.Info("Close database ...\n")
	ca.db.Close()

	clog.Info("Done\n")
}

func (ca *CA) get_ca_cert() ([]byte, error) {
	var cert []byte

	stmt := fmt.Sprintf("SELECT cert FROM certs WHERE is_ca=true ORDER BY serial DESC LIMIT 1;")
	if err := ca.db.QueryRow(stmt).Scan(&cert); err != nil {
		return nil, err
	}
	if ca.conf.Extra_ca != "" {
		if extra, err := ioutil.ReadFile(ca.conf.Extra_ca); err == nil {
			cert = append(cert, extra...)
		}
	}
	return cert, nil
}

func (ca *CA) create_revoked_list(tx *sql.Tx, number *big.Int, has_new_revoked_certs string) ([]byte, error) {
	stmt := fmt.Sprintf("SELECT serial,end,revoked_time FROM certs WHERE status='R' ORDER BY serial;")
	rows, err := tx.Query(stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificateList []pkix.RevokedCertificate

	for rows.Next() {
		var serial string
		var end string
		var revoked_time string

		err = rows.Scan(&serial, &end, &revoked_time)
		if err != nil {
			return nil, err
		}

		deadline, err := time.Parse(time.RFC3339, end)
		if err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			clog.Debug("Cert %s deadline already passed: %s\n", serial, end)
			continue
		}

		clog.Debug("Revoke %s/%s/%s\n", serial, end, revoked_time)

		serialNumber, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			return nil, errors.New("Invalid serial format")
		}
		revocationTime, err := time.Parse(time.RFC3339, revoked_time)
		if err != nil {
			return nil, err
		}
		rc := pkix.RevokedCertificate{SerialNumber: serialNumber, RevocationTime: revocationTime}
		certificateList = append(certificateList, rc)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	var ca_cert_bytes []byte
	stmt = fmt.Sprintf("SELECT cert FROM certs WHERE is_ca=true ORDER BY serial DESC LIMIT 1;")
	err = tx.QueryRow(stmt).Scan(&ca_cert_bytes)
	if err != nil {
		return nil, err
	}
	ca_cert, err := load_cert(ca_cert_bytes)
	if err != nil {
		return nil, err
	}

	template := x509.RevocationList{
		RevokedCertificates: certificateList,
		Number:              number,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 0, crlNextUpdate),
	}
	derBytes, err := x509.CreateRevocationList(rand.Reader, &template, ca_cert, ca.key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err = pem.Encode(&buf, &pem.Block{Type: "X509 CRL", Bytes: derBytes}); err != nil {
		return nil, err
	}
	crl_bytes := buf.Bytes()

	var sqlstmt *sql.Stmt
	if sqlstmt, err = tx.Prepare("INSERT INTO revokedlist(number,this_update,next_update,crl) VALUES(?,?,?,?)"); err != nil {
		return nil, err
	}
	defer sqlstmt.Close()
	if _, err = sqlstmt.Exec(bytes_to_hex_string(number.Bytes()),
		template.ThisUpdate.Format(time.RFC3339),
		template.NextUpdate.Format(time.RFC3339),
		crl_bytes); err != nil {
		return nil, err
	}

	if has_new_revoked_certs == "yes" {
		stmt = fmt.Sprintf("UPDATE config SET value='no' WHERE key='has_new_revoked_certs'")
		if _, err = tx.Exec(stmt); err != nil {
			return nil, err
		}
	}

	return crl_bytes, nil
}

func (ca *CA) get_crl() ([]byte, error) {
	tx, err := ca.db.Begin()
	if err != nil {
		return nil, err
	}

	// See if there're new revoked certs
	var has_new_revoked_certs string
	stmt := fmt.Sprintf("SELECT value FROM config WHERE key='has_new_revoked_certs';")
	err = tx.QueryRow(stmt).Scan(&has_new_revoked_certs)
	if err != nil && err != sql.ErrNoRows {
		tx.Rollback()
		return nil, err
	}

	var number string
	var next_update string
	var crl []byte
	stmt = fmt.Sprintf("SELECT number,next_update,crl FROM revokedlist ORDER BY number DESC LIMIT 1;")
	err = tx.QueryRow(stmt).Scan(&number, &next_update, &crl)
	if err != nil && err != sql.ErrNoRows {
		tx.Rollback()
		return nil, err
	}
	if err == sql.ErrNoRows {
		crl_number, err := get_serial_number(60)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		crl_bytes, err := ca.create_revoked_list(tx, crl_number, has_new_revoked_certs)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		tx.Commit()
		return crl_bytes, nil
	}

	var crl_bytes []byte
	if has_new_revoked_certs == "yes" {
		crl_number, ok := new(big.Int).SetString(number, 16)
		if ok {
			crl_number.Add(crl_number, big.NewInt(1))
			crl_bytes, err = ca.create_revoked_list(tx, crl_number, has_new_revoked_certs)
		} else {
			err = errors.New("Invalid number format")
		}
	} else {
		var deadline time.Time

		deadline, err = time.Parse(time.RFC3339, next_update)
		if err == nil {
			deadline = deadline.AddDate(0, 0, -crlUpdate)
			if time.Now().After(deadline) {
				crl_number, ok := new(big.Int).SetString(number, 16)
				if ok {
					crl_number.Add(crl_number, big.NewInt(1))
					crl_bytes, err = ca.create_revoked_list(tx, crl_number, has_new_revoked_certs)
				} else {
					err = errors.New("Invalid number format")
				}
			} else {
				crl_bytes = crl[:]
			}
		}
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	tx.Commit()
	return crl_bytes, nil
}

func load_csr(req string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(req))
	if block == nil {
		return nil, errors.New("Invalid req format")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func load_cert(cert_bytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(cert_bytes)
	if block == nil {
		return nil, errors.New("Invalid cert format")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func load_certs(cert_bytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(cert_bytes) > 0 {
		var block *pem.Block
		block, cert_bytes = pem.Decode(cert_bytes)
		if block == nil {
			return nil, errors.New("Invalid cert format")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (ca *CA) do_sign(tx *sql.Tx, subjectKeyId []byte, csr *x509.CertificateRequest, pub *ecdsa.PublicKey, valid_for int) ([]byte, error) {
	var status string
	var end string
	var cert_bytes []byte
	stmt := fmt.Sprintf("SELECT status,end,cert FROM certs WHERE ski='%s' ORDER BY serial DESC LIMIT 1;", bytes_to_hex_string(subjectKeyId))
	err := tx.QueryRow(stmt).Scan(&status, &end, &cert_bytes)
	if err == nil {
		if status == "R" {
			return nil, e_deny_revoked
		}

		deadline, err := time.Parse(time.RFC3339, end)
		if err != nil {
			return nil, err
		}
		deadline = deadline.AddDate(0, 0, -certUpdate)
		if time.Now().Before(deadline) {
			return cert_bytes, nil
		}
	} else if err == sql.ErrNoRows {
		var enable_sign string
		stmt = fmt.Sprintf("SELECT value FROM config WHERE key='enable_sign';")
		err = tx.QueryRow(stmt).Scan(&enable_sign)
		if err != nil {
			return nil, err
		}
		if enable_sign != "yes" {
			return nil, e_deny
		}
	} else {
		return nil, err
	}

	var ca_cert_bytes []byte
	stmt = fmt.Sprintf("SELECT cert FROM certs WHERE is_ca=true ORDER BY serial DESC LIMIT 1;")
	err = tx.QueryRow(stmt).Scan(&ca_cert_bytes)
	if err != nil {
		return nil, err
	}
	ca_cert, err := load_cert(ca_cert_bytes)
	if err != nil {
		return nil, err
	}

	var serial string
	stmt = fmt.Sprintf("SELECT serial FROM certs ORDER BY serial DESC LIMIT 1;")
	err = tx.QueryRow(stmt).Scan(&serial)
	if err != nil {
		return nil, err
	}
	serialNumber, ok := new(big.Int).SetString(serial, 16)
	if !ok {
		return nil, errors.New("Invalid serial format")
	}
	serialNumber.Add(serialNumber, big.NewInt(1))

	keyUsage := x509.KeyUsageDigitalSignature

	notBefore := time.Now().AddDate(0, 0, -1)
	if valid_for <= 0 {
		valid_for = ca.conf.Valid_for
	}
	notAfter := notBefore.AddDate(0, 0, valid_for)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject, // ToRDNSequence()/FillFromRDNSequence() not needed
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		SubjectKeyId: subjectKeyId[:],

		DNSNames: csr.DNSNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca_cert, pub, ca.key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}

	cert_bytes = buf.Bytes()
	cert, _ := load_cert(cert_bytes)

	clog.Info("serial: %s\n", bytes_to_hex_string(cert.SerialNumber.Bytes()))
	clog.Info("cname: %s\n", cert.Subject.CommonName)
	clog.Info("begin: %s\n", cert.NotBefore.Format(time.RFC3339))
	clog.Info("end: %s\n", cert.NotAfter.Format(time.RFC3339))
	clog.Info("ski: %s\n", bytes_to_hex_string(cert.SubjectKeyId))

	var sqlstmt *sql.Stmt
	if sqlstmt, err = tx.Prepare("INSERT INTO certs(serial,name,ski,is_ca,begin,end,status,cert) VALUES(?,?,?,?,?,?,?,?)"); err != nil {
		return nil, err
	}
	defer sqlstmt.Close()
	if _, err = sqlstmt.Exec(bytes_to_hex_string(cert.SerialNumber.Bytes()),
		cert.Subject.CommonName,
		bytes_to_hex_string(cert.SubjectKeyId),
		cert.IsCA,
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339),
		"V",
		cert_bytes); err != nil {
		return nil, err
	}

	return cert_bytes, nil
}

func (ca *CA) sign(req string, valid_for int) (string, error) {
	csr, err := load_csr(req)
	if err != nil {
		return "", err
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("Not an ECDSA public key\n")
	}
	pub_bytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	subjectKeyId := sha1.Sum(pub_bytes)

	tx, err := ca.db.Begin()
	if err != nil {
		return "", err
	}
	cert_bytes, err := ca.do_sign(tx, subjectKeyId[:], csr, pub, valid_for)
	if err != nil {
		tx.Rollback()
		return "", err
	}
	tx.Commit()
	return string(cert_bytes), nil
}

func (ca *CA) Show(req string, local bool) (string, error) {
	var stmt string

	if req == "ca" {
		var cert []byte

		stmt = fmt.Sprintf("SELECT cert FROM certs WHERE is_ca=true ORDER BY serial DESC LIMIT 1;")
		err := ca.db.QueryRow(stmt).Scan(&cert)
		if err != nil {
			clog.Warn("%v\n", err)
			return "", err
		}
		clog.Info("\n%s", cert)
		return "", nil
	} else if req == "crl" {
		var crl []byte

		stmt = fmt.Sprintf("SELECT crl FROM revokedlist ORDER BY number DESC LIMIT 1;")
		err := ca.db.QueryRow(stmt).Scan(&crl)
		if err != nil {
			clog.Warn("%v\n", err)
			return "", err
		}
		clog.Info("\n%s", crl)
		return "", nil
	} else if is_serial_number(req) {
		stmt = fmt.Sprintf("SELECT serial,name,ski,is_ca,begin,end,status FROM certs WHERE serial='%s';", req)
	} else if is_ski(req) {
		stmt = fmt.Sprintf("SELECT serial,name,ski,is_ca,begin,end,status FROM certs WHERE ski='%s' ORDER BY serial;", req)
	} else {
		clog.Debug("Show all certs ...\n")
		stmt = fmt.Sprintf("SELECT serial,name,ski,is_ca,begin,end,status FROM certs ORDER BY serial;")
	}

	rows, err := ca.db.Query(stmt)
	if err != nil {
		clog.Warn("%v\n", err)
		return "", err
	}
	defer rows.Close()

	var count int
	b := &strings.Builder{}

	if local {
		clog.Info("serial|name|ski|is_ca|begin|end|status\n")
	} else {
		count = 0
		b.WriteString("{\n\"code\":0,\"data\":{\n\"data_list\":[\n")
	}
	for rows.Next() {
		var serial string
		var name string
		var ski string
		var is_ca bool
		var begin string
		var end string
		var status string

		err = rows.Scan(&serial, &name, &ski, &is_ca, &begin, &end, &status)
		if err != nil {
			clog.Warn("%v\n", err)
			return "", err
		}

		if local {
			clog.Info("%s|%s|%s|%t|%s|%s|%s\n", serial, name, ski, is_ca, begin, end, status)
		} else {
			if count >= 1 {
				b.WriteString(fmt.Sprintf(",{\"serial\":\"%s\",\"name\":\"%s\",\"ski\":\"%s\",\"is_ca\":\"%t\",\"begin\":\"%s\",\"end\":\"%s\",\"status\":\"%s\"}", serial, name, ski, is_ca, begin, end, status))
			} else {
				b.WriteString(fmt.Sprintf("{\"serial\":\"%s\",\"name\":\"%s\",\"ski\":\"%s\",\"is_ca\":\"%t\",\"begin\":\"%s\",\"end\":\"%s\",\"status\":\"%s\"}", serial, name, ski, is_ca, begin, end, status))
			}
			count += 1
		}
	}
	err = rows.Err()
	if err != nil {
		clog.Warn("%v\n", err)
		return "", err
	}

	if local {
		return "", nil
	}

	b.WriteString(fmt.Sprintf("\n],\n\"total\":%d\n}\n}\n", count))
	return b.String(), nil
}

func (ca *CA) getBundle(cn string, valid_for int) (key_buf, cert_buf, ca_buf, crl_buf []byte, err error) {
	// FIXME: 'cn' should be a valid CommonName
	if len(cn) <= 0 {
		err = errors.New("Invalid CN")
		return
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: key})
	if err != nil {
		return
	}
	key_buf = buf.Bytes()

	params := &CaParams{Country: ca.conf.Country, Organization: ca.conf.Organization, OrganizationalUnit: ca.conf.OrganizationalUnit}
	params.CommonName = cn
	// Certificate Signing Request
	csr, err := CreateCertificateRequest(params, priv)
	if err != nil {
		return
	}
	cert_str, err := ca.sign(string(csr), valid_for)
	if err != nil {
		return
	}
	cert_buf = []byte(cert_str)

	ca_buf, err = ca.get_ca_cert()
	if err != nil {
		return
	}

	crl_buf, err = ca.get_crl()
	return
}

func (ca *CA) Revoke(req string) {
	if !is_serial_number(req) {
		clog.Warn("Invalid serial number format: %s\n", req)
		return
	}

	tx, err := ca.db.Begin()
	if err != nil {
		clog.Warn("%v\n", err)
		return
	}

	var is_ca bool
	var end string
	var status string
	var deadline time.Time
	stmt := fmt.Sprintf("SELECT is_ca,end,status FROM certs WHERE serial='%s';", req)
	err = tx.QueryRow(stmt).Scan(&is_ca, &end, &status)
	if err != nil {
		clog.Warn("%v\n", err)
		goto rollback
	}
	if is_ca == true {
		clog.Warn("You can't revoke an CA cert.\n")
		goto rollback
	}
	if status == "R" {
		clog.Warn("Cert already revoked.\n")
		goto rollback
	}
	deadline, err = time.Parse(time.RFC3339, end)
	if err != nil {
		clog.Warn("%s: %v\n", end, err)
		goto rollback
	}
	if time.Now().After(deadline) {
		clog.Warn("Cert %s deadline already passed: %s\n", req, end)
		goto rollback
	}

	stmt = fmt.Sprintf("UPDATE certs SET status='R',revoked_time='%s' WHERE serial='%s'", time.Now().Format(time.RFC3339), req)
	if _, err = tx.Exec(stmt); err != nil {
		clog.Warn("%v\n", err)
		goto rollback
	}

	stmt = fmt.Sprintf("UPDATE config SET value='yes' WHERE key='has_new_revoked_certs'")
	if _, err = tx.Exec(stmt); err != nil {
		clog.Warn("%v\n", err)
		goto rollback
	}

	tx.Commit()

	clog.Info("Cert %s revoked.\n", req)
	return

rollback:
	tx.Rollback()
	return
}

func (ca *CA) Enable_sign(req string) {
	if req != "yes" && req != "no" {
		clog.Warn("Invalid req: %s\n", req)
		return
	}

	tx, err := ca.db.Begin()
	if err != nil {
		clog.Warn("%v\n", err)
		return
	}

	var enable_sign string
	stmt := fmt.Sprintf("SELECT value FROM config WHERE key='enable_sign'")
	err = tx.QueryRow(stmt).Scan(&enable_sign)
	if err != nil {
		clog.Warn("%v\n", req)
		goto rollback
	}
	if enable_sign == req {
		if req == "yes" {
			clog.Info("Remote signing already enabled.\n")
		} else {
			clog.Info("Remote signing already disabled.\n")
		}
		goto rollback
	}
	stmt = fmt.Sprintf("UPDATE config SET value='%s' WHERE key='enable_sign'", req)
	if _, err = tx.Exec(stmt); err != nil {
		clog.Warn("%v\n", req)
		goto rollback
	}

	tx.Commit()

	if req == "yes" {
		clog.Info("Remote signing enabled.\n")
	} else {
		clog.Info("Remote signing disabled.\n")
	}
	return

rollback:
	tx.Rollback()
	return
}

func SetCaParams(params *CaParams, kv string) error {
	kvs := strings.Split(kv, "=")
	if len(kvs) != 2 {
		return errors.New("Invalid kv format: not exactly 2 fields")
	}
	switch strings.ToUpper(kvs[0]) {
	case "C":
		params.Country = kvs[1]
	case "O":
		params.Organization = kvs[1]
	case "OU":
		params.OrganizationalUnit = kvs[1]
	case "ST":
		params.Province = kvs[1]
	case "L":
		if len(kvs[1]) != 4 {
			return errors.New("Invalid kv format: 'L' value length should be 4")
		}
		params.Locality = []string{kvs[1][0:2], kvs[1][2:4]}
	case "T":
		params.Title = kvs[1]
	case "CN":
		params.CommonName = kvs[1]
	default:
		return fmt.Errorf("Invalid kv format: unknown key '%s'", kvs[0])
	}
	return nil
}

// go/src/crypto/x509/pkix/pkix.go
var (
	oidCountry            = []int{2, 5, 4, 6}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidPostalCode         = []int{2, 5, 4, 17}

	oidTitle              = []int{2, 5, 4, 12}
)

// appendRDNs appends a relativeDistinguishedNameSET to the given RDNSequence
// and returns the new value. The relativeDistinguishedNameSET contains an
// attributeTypeAndValue for each of the given values. See RFC 5280, A.1, and
// search for AttributeTypeAndValue.
//func (n Name) appendRDNs(in RDNSequence, values []string, oid asn1.ObjectIdentifier) RDNSequence {
func appendRDNs(in pkix.RDNSequence, values []string, oid asn1.ObjectIdentifier) pkix.RDNSequence {
	//if len(values) == 0 || oidInAttributeTypeAndValue(oid, n.ExtraNames) {
	if len(values) == 0 {
		return in
	}

	s := make([]pkix.AttributeTypeAndValue, len(values))
	for i, value := range values {
		s[i].Type = oid
		s[i].Value = value
	}

	return append(in, s)
}

var (
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

func CreateCertificateRequest(params *CaParams, priv *ecdsa.PrivateKey) ([]byte, error) {
	var template *x509.CertificateRequest

	if len(params.Title) > 0 {
		var rawsub pkix.RDNSequence

		rawsub = appendRDNs(rawsub, []string{params.Country}, oidCountry)
		rawsub = appendRDNs(rawsub, []string{params.Organization}, oidOrganization)
		rawsub = appendRDNs(rawsub, []string{params.Province}, oidProvince)
		for _, l := range params.Locality {
			rawsub = appendRDNs(rawsub, []string{l}, oidLocality)
		}
		rawsub = appendRDNs(rawsub, []string{params.OrganizationalUnit}, oidOrganizationalUnit)
		rawsub = appendRDNs(rawsub, []string{params.Title}, oidTitle)
		rawsub = appendRDNs(rawsub, []string{params.CommonName}, oidCommonName)

		asn1sub, _ := asn1.Marshal(rawsub)

		var extension []pkix.Extension
		extension = append(extension, pkix.Extension{ Id: oidExtKeyUsageServerAuth })
		extension = append(extension, pkix.Extension{ Id: oidExtKeyUsageClientAuth })

		template = &x509.CertificateRequest{
			RawSubject: asn1sub,
			ExtraExtensions: extension,
		}
	} else {
		template = &x509.CertificateRequest{
			Subject: pkix.Name{
				Country:            []string{params.Country},
				Organization:       []string{params.Organization},
				OrganizationalUnit: []string{params.OrganizationalUnit},
				CommonName:         params.CommonName,
			},
			DNSNames: []string{params.CommonName},
		}
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (ca *CA) Sign(req string, valid_for int) (string, error) {
	cert_request, err := ioutil.ReadFile(req)
	if err != nil {
		return "", err
	}
	return ca.sign(string(cert_request), valid_for)
}

func VerifyCert(ca_file string, cert_bytes []byte) error {
	ca_cert_bytes, err := ioutil.ReadFile(ca_file)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca_cert_bytes) {
		return errors.New("pool: failed to append certificate")
	}

	cert, err := load_cert(cert_bytes)
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err = cert.Verify(opts); err != nil {
		return err
	}
	return nil
}

func SameIssuer(old_bytes, new_bytes []byte) bool {
	o, err := load_cert(old_bytes)
	if err != nil {
		return false
	}
	// We can overwrite self issued/signed cert ...
	if bytes.Equal(o.RawIssuer, o.RawSubject) {
		return true
	}
	n, err := load_cert(new_bytes)
	if err != nil {
		return false
	}
	return bytes.Equal(o.RawIssuer, n.RawIssuer)
}

func VerifyCRL(ca_file string, crl_bytes []byte) error {
	ca_cert_bytes, err := ioutil.ReadFile(ca_file)
	if err != nil {
		return err
	}
	ca_certs, err := load_certs(ca_cert_bytes)
	if err != nil {
		return err
	}

	list, err := x509.ParseCRL(crl_bytes)
	if err != nil {
		return err
	}

	for _, c := range ca_certs {
		if err = c.CheckCRLSignature(list); err == nil {
			return nil
		}
	}
	return errors.New("CRL verify failed")
}

func ShowCert(ca_file, cert_file, crl_file string) {
	cert_bytes, err := ioutil.ReadFile(ca_file)
	if err != nil {
		clog.Warn("%v\n", err)
	} else {
		certs, err := load_certs(cert_bytes)
		if err != nil {
			clog.Warn("%v\n", err)
		} else {
			for i, c := range certs {
				clog.Info("CA: %d\n", i)
				clog.Info("  issuer : %v\n", c.Issuer)
				clog.Info("  subject: %v\n", c.Subject)
				clog.Info("  begin  : %v\n", c.NotBefore.Format(time.RFC3339))
				clog.Info("  end    : %v\n", c.NotAfter.Format(time.RFC3339))
			}
		}
	}

	cert_bytes, err = ioutil.ReadFile(cert_file)
	if err != nil {
		clog.Warn("%v\n", err)
	} else {
		cert, err := load_cert(cert_bytes)
		if err != nil {
			clog.Warn("%v\n", err)
		} else {
			clog.Info("Cert:\n")
			clog.Info("  issuer : %v\n", cert.Issuer)
			clog.Info("  subject: %v\n", cert.Subject)
			clog.Info("  begin  : %v\n", cert.NotBefore.Format(time.RFC3339))
			clog.Info("  end    : %v\n", cert.NotAfter.Format(time.RFC3339))
		}
	}
}

func LoadPrivKey(key_file string) (*ecdsa.PrivateKey, error) {
	pb, err := ioutil.ReadFile(key_file)
	if err != nil {
		return nil, err
	}
	db, _ := pem.Decode(pb)
	if db == nil || (db.Type != "PRIVATE KEY" && !strings.HasSuffix(db.Type, " PRIVATE KEY")) {
		return nil, errors.New("Invalid private key format")
	}
	priv_interface, err := x509.ParsePKCS8PrivateKey(db.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := priv_interface.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Not an ECDSA private key")
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("Not an ECDSA P256 private key")
	}
	return priv, nil
}

func generate_key(key_file string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		clog.Fatal("Failed to generate private key: %v\n", err)
	}

	keyOut, err := os.OpenFile(key_file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		clog.Fatal("Failed to open %s for writing: %v\n", key_file, err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		clog.Fatal("Unable to marshal private key: %v\n", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		clog.Fatal("Failed to write data to %s: %v\n", key_file, err)
	}
	if err := keyOut.Close(); err != nil {
		clog.Fatal("Error closing %s: %v\n", key_file, err)
	}
	clog.Info("%s created.\n", key_file)
}
