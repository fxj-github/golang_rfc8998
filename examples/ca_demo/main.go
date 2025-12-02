package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
)

var (
	clog     = NewLog("CA")
	version string
)

func usage() {
	fmt.Printf("\n")
	fmt.Printf("Server usage:\n")
	fmt.Printf("  %s [-v level] [-p dir] { cinit | cinit_p256 } [ http_ip/http_port ]\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] cconfig key value\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] crun\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] show [ serial | ski | ca | crl ]\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] revoke serial\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] sign /path/to/request [ valid_for ]\n", os.Args[0])
	fmt.Printf("\n")

	fmt.Printf("Client usage:\n")
	fmt.Printf("  %s [-v level] [-p dir] update_ca_cert [ http_ip/http_port ]\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] update_crl [ http_ip/http_port ]\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] update_cert [ http_ip/http_port ]\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] gen_cert_request { cn | title } [ options ]\n", os.Args[0])
	fmt.Printf("  %s [-v level] [-p dir] show_cert\n", os.Args[0])
	fmt.Printf("\n")
}

func save_file(file string, data []byte) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

func main() {
	var verbose int
	var cwd = "./"

	flag.IntVar(&verbose, "v", 2, "Verbose level(0-4)")
	flag.StringVar(&cwd, "p", "./", "Working directory")
	flag.Usage = usage
	flag.CommandLine.SetOutput(os.Stdout)

	flag.Parse()

	SetVerbose("", int32(verbose))

	clog.Info("Version: %s\n", version)
	clog.Info("verbose: %d\n", verbose)
	clog.Info("Working directory: %s\n", cwd)
	if err := os.Chdir(cwd); err != nil {
		clog.Fatal("Chdir() failed: %s\n", err)
	}

	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}

	if flag.Arg(0) == "gen_cert_request" {
		if flag.NArg() < 2 ||
		   (flag.Arg(1) != "cn" && flag.Arg(1) != "title") {
			usage()
			os.Exit(1)
		}

		typ := flag.Arg(1)

		var params CaParams

		if typ == "cn" {
			params.Country = "CN"
			params.Organization = "EXAMPLE"
			params.OrganizationalUnit = "www.example.com"
		} else if typ == "title" {
			// params.Country =
			// params.Organization =
			// params.OrganizationalUnit =
			// params.Province =
			// params.Locality =
			// params.CommonName =
		}

		save_dir := "./"
		req := "test"

		priv, err := LoadPrivKey(key_file)
		if err != nil {
			clog.Fatal("%v\n", err)
		}
		if typ == "cn" {
			params.CommonName = req
		} else if typ == "title" {
			// params.Title =
		}

		for i := 2; i + 1 <= flag.NArg(); i++ {
			if err := SetCaParams(&params, flag.Arg(i)); err != nil {
				clog.Fatal("%v\n", err)
			}
		}

		csr, err := CreateCertificateRequest(&params, priv)
		if err != nil {
			clog.Fatal("%v\n", err)
		}

		f := save_dir + req + ".csr"
		if err = save_file(f, csr); err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Info("%s created.\n", f)

		os.Exit(0)
	} else if flag.Arg(0) == "cinit" {
		if flag.NArg() == 1 {
			if err := CInit("", true); err != nil {
				clog.Fatal("%s\n", err)
			}
			os.Exit(0)
		} else if flag.NArg() == 2 {
			if err := CInit(flag.Arg(1), true); err != nil {
				clog.Fatal("%s\n", err)
			}
			os.Exit(0)
		} else {
			usage()
			os.Exit(1)
		}
	} else if flag.Arg(0) == "cinit_p256" {
		if flag.NArg() == 1 {
			if err := CInit("", false); err != nil {
				clog.Fatal("%s\n", err)
			}
			os.Exit(0)
		} else if flag.NArg() == 2 {
			if err := CInit(flag.Arg(1), false); err != nil {
				clog.Fatal("%s\n", err)
			}
			os.Exit(0)
		} else {
			usage()
			os.Exit(1)
		}
	} else if flag.Arg(0) == "cconfig" {
		if flag.NArg() != 3 {
			usage()
			os.Exit(1)
		}
		if err := CSet(flag.Arg(1), flag.Arg(2)); err != nil {
			clog.Fatal("%v\n", err)
		}
		os.Exit(0)
	} else if flag.Arg(0) == "crun" {
		conf, err := CLoad(false)
		if err != nil {
			clog.Fatal("%s\n", err)
		}
		clog.Info("RESTFUL addr: %s/%d\n", conf.Http_ip, conf.Http_port)

		ca, err := NewCA(conf)
		if err != nil {
			clog.Fatal("%s\n", err)
		}

		ca.Run()

		os.Exit(0)
	} else if flag.Arg(0) == "show" {
		var req string

		if flag.NArg() == 2 {
			req = flag.Arg(1)
		} else if flag.NArg() != 1 {
			usage()
			os.Exit(1)
		}

		// make sure we're an CA
		_, err := CLoad(false)
		if err != nil {
			clog.Fatal("%s\n", err)
		}

		ca, err := NewCA_DB()
		if err != nil {
			clog.Fatal("%s\n", err)
		}

		ca.Show(req, true)

		ca.CloseDB()

		os.Exit(0)
	} else if flag.Arg(0) == "revoke" {
		if flag.NArg() != 2 {
			usage()
			os.Exit(1)
		}
		req := flag.Arg(1)

		// make sure we're an CA
		_, err := CLoad(false)
		if err != nil {
			clog.Fatal("%s\n", err)
		}

		ca, err := NewCA_DB()
		if err != nil {
			clog.Fatal("%s\n", err)
		}

		ca.Revoke(req)

		ca.CloseDB()

		os.Exit(0)
	} else if flag.Arg(0) == "sign" {
		if flag.NArg() != 2 && flag.NArg() != 3 {
			usage()
			os.Exit(1)
		}
		req := flag.Arg(1)

		valid_for := 0
		if flag.NArg() == 3 {
			v, err := strconv.ParseInt(flag.Arg(2), 10, 0)
			if err != nil {
				clog.Fatal("%s\n", err)
			}
			if int(v) <= 0 {
				clog.Fatal("Invalid valid_for: %s\n", flag.Arg(2))
			}
			valid_for = int(v)
		}

		// make sure we're an CA
		conf, err := CLoad(false)
		if err != nil {
			clog.Fatal("%s\n", err)
		}

		ca, err := NewCA(conf)
		if err != nil {
			clog.Fatal("%s\n", err)
		}

		cert, err := ca.Sign(req, valid_for)
		if err != nil {
			clog.Fatal("%s\n", err)
		}
		fmt.Printf("%s", cert)

		ca.CloseDB()

		os.Exit(0)
	} else if flag.Arg(0) == "update_ca_cert" {
		ca_ip := "127.0.0.1"
		ca_port := 10003

		var client *ca_client
		var err error
		if flag.NArg() == 1 {
			client, err = new_ca_client(fmt.Sprintf("%s,%d", ca_ip, ca_port))
		} else if flag.NArg() == 2 {
			client, err = new_ca_client(flag.Arg(1))
		} else {
			usage()
			os.Exit(1)
		}
		if err != nil {
			clog.Fatal("%v\n", err)
		}

		ca_cert, err := client.get_ca_cert_or_crl("get_ca_cert")
		if err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Debug("ca_cert: %s\n", ca_cert)

		b, _ := ioutil.ReadFile(ca_file)
		if bytes.Equal(ca_cert, b) {
			clog.Info("%s not changed, do nothing.\n", ca_file)
			os.Exit(0)
		}

		save_file(ca_file + ".backup", b)

		if err = save_file(ca_file, ca_cert); err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Info("%s Updated. You should run 'update_cert' and 'update_crl'.\n", ca_file)

		os.Exit(0)
	} else if flag.Arg(0) == "update_crl" {
		ca_ip := "127.0.0.1"
		ca_port := 10003

		var client *ca_client
		var err error
		if flag.NArg() == 1 {
			client, err = new_ca_client(fmt.Sprintf("%s,%d", ca_ip, ca_port))
		} else if flag.NArg() == 2 {
			client, err = new_ca_client(flag.Arg(1))
		} else {
			usage()
			os.Exit(1)
		}
		if err != nil {
			clog.Fatal("%v\n", err)
		}

		crl, err := client.get_ca_cert_or_crl("get_crl")
		if err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Debug("crl: %s\n", crl)

		if err = VerifyCRL(ca_file, crl); err != nil {
			clog.Fatal("CRL verify failed: %v. Maybe you have not run 'update_ca_cert'?\n", err)
		}

		b, _ := ioutil.ReadFile(crl_file)
		if bytes.Equal(crl, b) {
			clog.Info("%s not changed, do nothing.\n", crl_file)
			os.Exit(0)
		}

		save_file(crl_file + ".backup", b)

		if err = save_file(crl_file, crl); err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Info("%s Updated.\n", crl_file)

		os.Exit(0)
	} else if flag.Arg(0) == "update_cert" {
		ca_ip := "127.0.0.1"
		ca_port := 10003

		var client *ca_client
		var err error
		if flag.NArg() == 1 {
			client, err = new_ca_client(fmt.Sprintf("%s,%d", ca_ip, ca_port))
		} else if flag.NArg() == 2 {
			client, err = new_ca_client(flag.Arg(1))
		} else {
			usage()
			os.Exit(1)
		}
		if err != nil {
			clog.Fatal("%v\n", err)
		}

		params, err := client.get_ca_params()
		if err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Info("C:%s O:%s OU:%s\n", params.Country, params.Organization, params.OrganizationalUnit)

		priv, err := LoadPrivKey(key_file)
		if err != nil {
			clog.Fatal("%v\n", err)
		}

		// read from old cert file?
		params.CommonName = "test"
		csr, err := CreateCertificateRequest(params, priv)
		if err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Debug("csr: %s", csr)

		cert, err := client.sign([]byte(csr))
		if err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Debug("cert: %s", cert)

		if err = VerifyCert(ca_file, cert); err != nil {
			clog.Fatal("Cert verify failed: %v. Maybe you have not run 'update_ca_cert'?\n", err)
		}

		b, _ := ioutil.ReadFile(cert_file)
		if bytes.Equal(cert, b) {
			clog.Info("%s not changed, do nothing.\n", cert_file)
			os.Exit(0)
		}
		if len(b) > 0 && !SameIssuer(b, cert) {
			clog.Info("Issuer changed, do nothing.\n")
			os.Exit(0)
		}

		save_file(cert_file + ".backup", b)

		if err = save_file(cert_file, cert); err != nil {
			clog.Fatal("%v\n", err)
		}
		clog.Info("%s Updated.\n", cert_file)

		os.Exit(0)
	} else if flag.Arg(0) == "show_cert" {
		ShowCert(ca_file, cert_file, crl_file)

		os.Exit(0)
	}

	usage()
	os.Exit(1)
}
