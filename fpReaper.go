/*

Exciting Licence Info.....

This file is part of fpReaper.

# Lee's Shitheads Prohibited Licence (loosely based on the BSD simplified licence)
Copyright 2021 Lee Brotherston
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. You are not a member of law enforcement, and you do not work for any government or private organization that conducts or aids surveillance (e.g., signals intelligence, Palantir).
4. You are not associated with any groups which are aligned with Racist, Homophobic, Transphobic, TERF, Mysogynistic, "Pro Life" (anti-womens-choice), or other shithead values.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/LeeBrotherston/dactyloscopy"
	_ "github.com/joho/godotenv/autoload" // Nice autoload for godotenv so we can use a .env file or real environment variables
)

// Global blocklist map (temp)
var blocklist = map[string]bool{}

func main() {
	var fpJSON = flag.String("fingerprint", "./fpReaper.json", "the fingerprint file")
	var interfaceName = flag.String("interface", "", "Specify the interface")
	var listenAddress = flag.String("listen", ":443", "address for proxy to listen to")
	flag.Parse()

	// Open JSON file tlsproxy.json
	file, err := ioutil.ReadFile(*fpJSON)
	if err != nil {
		log.Printf("Problem: File error opening fingerprint file: %v\n", err)
		log.Printf("You may wish to try: cat fingerprints.json | jq -scM '' > tlsProxy.json to update\n")
		os.Exit(1)
	}

	// Parse that JSON file
	var jsontype []dactyloscopy.FingerprintFile
	err = json.Unmarshal(file, &jsontype)
	if err != nil {
		log.Fatalf("JSON error: %v", err)
		os.Exit(1)
	}

	// Create the bare fingerprintDB map structure
	fingerprintDBNew := make(map[uint64]string)

	// populate the fingerprintDB map
	for k := range jsontype {
		dactyloscopy.Add(dactyloscopy.Ftop(jsontype[k]), fingerprintDBNew)
	}

	log.Printf("Loaded %v fingerprints\n", len(jsontype))

	// Use the go concurrency magic to run the sniffer at the same time as a webserver, because of course
	go doSniff(*interfaceName, fingerprintDBNew)

	// OK so let's run a webserver that we're going to be sniffing

	// generate a `Certificate` struct
	cert, _ := tls.LoadX509KeyPair("localhost.crt", "localhost.key")

	// create a custom server with `TLSConfig`
	s := &http.Server{
		Addr:    *listenAddress,
		Handler: nil, // use `http.DefaultServeMux`
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// handle `/` route
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		log.Printf("%v %v ", req.RemoteAddr, req.UserAgent())
		fmt.Fprint(res, "Hello Custom World!")
	})

	// run server on port
	log.Fatal(s.ListenAndServeTLS("", ""))

}

// check is a (probably over) simple function to wrap errors that will always be fatal
func check(e error) {
	if e != nil {
		panic(e)
	}
}
