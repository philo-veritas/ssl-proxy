package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/suyashkumar/ssl-proxy/gen"
	"github.com/suyashkumar/ssl-proxy/reverseproxy"
)

var (
	to           = flag.String("to", "http://127.0.0.1:80", "the address and port for which to proxy requests to")
	fromURL      = flag.String("from", "127.0.0.1:4430", "the tcp address and port this proxy should listen for requests on")
	certFile     = flag.String("cert", "", "path to a tls certificate file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
	keyFile      = flag.String("key", "", "path to a private key file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
	redirectHTTP = flag.Bool("redirectHTTP", false, "if true, redirects http requests from port 80 to https at your fromURL")
)

const (
	DefaultCertFile = "cert.pem"
	DefaultKeyFile  = "key.pem"
	HTTPSPrefix     = "https://"
	HTTPPrefix      = "http://"
)

func makeRedirectTLSHandler() http.Handler {
	redirectTLS := func(w http.ResponseWriter, r *http.Request) {
		redirectTo := "https://" + r.Host + r.RequestURI
		log.Println("host: ", r.Host)
		log.Printf("Redirecting from %s to %s", r.Host+r.RequestURI, redirectTo)
		http.Redirect(w, r, redirectTo, http.StatusMovedPermanently)
	}
	return http.HandlerFunc(redirectTLS)
}

func makeProxyHandler() {
	// Parse the toURL
	// toURL, err := url.Parse(*to)
	// if err != nil {
	// 	log.Fatalf("Could not parse toURL: %v", err)
	// }
	//
	// // Create the proxy
	// proxy := reverseproxy.NewSingleHostReverseProxy(toURL)
	//
	// // Return the proxy
	// return proxy
}

var _ http.Handler = &httputil.ReverseProxy{}

func main() {
	flag.Parse()

	certSpecified := *certFile != ""
	keySpecified := *keyFile != ""

	// Determine if we need to generate self-signed certs
	if !certSpecified || !keySpecified {
		// Use default file paths
		log.Printf("No cert or key file provided, generating self-signed certs")
		*certFile = DefaultCertFile
		*keyFile = DefaultKeyFile

		log.Printf("No existing cert or key specified, generating some self-signed certs for use (%s, %s)\n", *certFile, *keyFile)

		// Generate new keys
		certBuf, keyBuf, fingerprint, err := gen.Keys(365 * 24 * time.Hour)
		if err != nil {
			log.Fatal("Error generating default keys", err)
		}

		certOut, err := os.Create(*certFile)
		if err != nil {
			log.Fatal("Unable to create cert file", err)
		}
		certOut.Write(certBuf.Bytes())

		keyOut, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatal("Unable to create the key file", err)
		}
		keyOut.Write(keyBuf.Bytes())

		log.Printf("SHA256 Fingerprint: % X", fingerprint)

	}

	// Ensure the to-URL is in the right form
	if !strings.HasPrefix(*to, HTTPPrefix) && !strings.HasPrefix(*to, HTTPSPrefix) {
		*to = HTTPPrefix + *to
		log.Println("Assuming -to URL is using http://")
	}

	// Parse to-URL as a URL
	toURL, err := url.Parse(*to)
	if err != nil {
		log.Fatal("Unable to parse 'to' url: ", err)
	}

	// Setup reverse proxy ServeMux
	proxyHandler := reverseproxy.Build(toURL)
	mux := http.NewServeMux()
	mux.Handle("/", proxyHandler)

	log.Printf(green("Proxying calls from https://%s (SSL/TLS) to %s"), *fromURL, toURL)

	// Redirect http requests on port 80 to TLS port using https
	if *redirectHTTP {
		// TODO: ?
		// Redirect to fromURL by default, unless a domain is specified--in that case, redirect using the public facing
		// domain
		redirectTLSHandler := makeRedirectTLSHandler()
		go func() {
			log.Printf("Also redirecting https requests on port 80 to 443")
			err := http.ListenAndServe(":80", redirectTLSHandler)
			if err != nil {
				log.Println("HTTP redirection server failure")
				log.Println(err)
			}
		}()
	}

	// Domain is not provided, serve TLS using provided/generated certificate files
	log.Fatal(http.ListenAndServeTLS(*fromURL, *certFile, *keyFile, mux))

}

// green takes an input string and returns it with the proper ANSI escape codes to render it green-colored
// in a supported terminal.
// TODO: if more colors used in the future, generalize or pull in an external pkg
func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}
