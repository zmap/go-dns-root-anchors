package rootanchors_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	rootanchors "github.com/zmap/go-dns-root-anchors"
)

// TestRootDNSKEYValidation tests DNSKEY validation against the root DS anchor.
func TestRootDNSKEYValidation(t *testing.T) {
	dnsKeys, err := queryRootKSK()
	if err != nil {
		t.Fatalf("Failed to query root DNSKEY records: %v", err)
	}
	t.Logf("DNSKEY records: %v", dnsKeys)

	dsRecords := rootanchors.GetDSRecords()
	if err != nil {
		t.Fatalf("Failed to get DS records from trust anchor: %v", err)
	}
	t.Logf("DS records: %v", dsRecords)

	for _, key := range dnsKeys {
		authenticDS, ok := dsRecords[key.KeyTag()]
		if !ok {
			t.Fatalf("DS record not found for DNSKEY with key tag %d", key.KeyTag())
		}

		computedDS := key.ToDS(authenticDS.DigestType)
		computedDigest := strings.ToUpper(computedDS.Digest)
		t.Logf("Authentic digest: %s, computed digest: %s", authenticDS.Digest, computedDigest)
		if computedDigest != authenticDS.Digest {
			t.Fatalf("DS record mismatch for DNSKEY with key tag %d", key.KeyTag())
		}
	}
}

// queryRootKSK queries the KSK records for the root zone (".").
func queryRootKSK() ([]*dns.DNSKEY, error) {
	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(".", dns.TypeDNSKEY)
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return nil, fmt.Errorf("failed to query root DNSKEY: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("invalid answer for root DNSKEY query: %v", r.Rcode)
	}

	// Collect DNSKEY records from the response.
	var dnsKeys []*dns.DNSKEY
	for _, rr := range r.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			if key.Flags == 257 {
				dnsKeys = append(dnsKeys, key)
			}
		}
	}

	return dnsKeys, nil
}
