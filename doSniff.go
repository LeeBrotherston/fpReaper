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
	"encoding/hex"
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/LeeBrotherston/dactyloscopy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func doSniff(device string, fingerprintDBNew map[uint64]string) {

	db := setupDB()

	// Open device
	// the 0 and true refer to snaplen and promisc mode.  For now we always want these.
	handle, err := pcap.OpenLive(device, 0, true, pcap.BlockForever)
	check(err)
	// Yes yes, I know... But offsetting this to the kernel *drastically* reduces processing time
	err = handle.SetBPFFilter("(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))")
	check(err)
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Use netflow to obtain source and dest.  This will be useful in the future when tracking
		// data in multiple directinos
		netFlow := packet.NetworkLayer().NetworkFlow()
		src, dst := netFlow.Endpoints()

		// Locate the payload to send the the tlsFingerprint() function
		payload := packet.ApplicationLayer()
		fingerprintOutput, fpDetail, fpHash := dactyloscopy.TLSFingerprint(payload.Payload(), fingerprintDBNew)

		// Populate an event struct
		var event Event

		// Because netflow is set to network layer src and dst will be IP addresses
		src, dst = netFlow.Endpoints()
		event.IPSrc = src.String()
		event.IPDst = dst.String()

		event.TimeStamp = packet.Metadata().Timestamp

		// Decode the TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)

		event.SrcPort = uint16(tcp.SrcPort)
		event.DstPort = uint16(tcp.DstPort)

		event.IPVersion = src.EndpointType().String()

		event.SNI = string(fingerprintOutput.Hostname)

		event.Event = "log"

		event.FPHash = strconv.FormatUint(fpHash, 16)

		jsonOut, _ := json.Marshal(event)

		// Some output....
		log.Printf("%s -> %s : %s : %s", src, dst, fingerprintOutput.FingerprintName, jsonOut)
		log.Printf("%s %s %s", hex.EncodeToString(fpDetail.Ciphersuite),
			hex.EncodeToString(fpDetail.Extensions), hex.EncodeToString(fpDetail.RecordTLSVersion))
		rows, success := sqlSingleShot(db, sqlInsertFingerprintDB,
			hex.EncodeToString(fpDetail.RecordTLSVersion),
			hex.EncodeToString(fpDetail.TLSVersion),
			hex.EncodeToString(fpDetail.Ciphersuite),
			hex.EncodeToString(fpDetail.Compression),
			hex.EncodeToString(fpDetail.Extensions),
			hex.EncodeToString(fpDetail.ECurves),
			hex.EncodeToString(fpDetail.SigAlg),
			hex.EncodeToString(fpDetail.EcPointFmt),
			fpDetail.Grease,
			hex.EncodeToString(fpDetail.SupportedVersions),
			hex.EncodeToString(packet.Data()))
		if success == true {
			log.Printf("Added %d rows", rows)
		}

	}

}

// Event structs are used to express events via the API
type Event struct {
	//EventID    [32]string `json:"event_id"`		// Generated serverside
	Event     string    `json:"event"`
	FPHash    string    `json:"fp_hash,omitempty"`
	IPVersion string    `json:"ip_version"`
	IPDst     string    `json:"ipv4_dst"`
	IPSrc     string    `json:"ipv4_src"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	TimeStamp time.Time `json:"timestamp"`
	//	TLSVersion  uint16    `json:"tls_version"`  // Part of the fingerprint, doesn't need to be stored here
	SNI string `json:"server_name"`
	//Fingerprint `json:"fingerprint,omitempty"`
}
