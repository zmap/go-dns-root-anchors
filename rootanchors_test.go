package rootanchors_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zmap/dns"
	rootanchors "github.com/zmap/go-dns-root-anchors"
)

// TestRootDSValidation checks root KSK against DS records from root trust anchor.
func TestRootDSValidation(t *testing.T) {
	dnsKeys, err := queryRootKSK()
	if err != nil {
		t.Fatalf("Failed to query root DNSKEY records: %v", err)
	}
	t.Logf("DNSKEY records: %v", dnsKeys)

	dsRecords := rootanchors.GetValidDSRecords()
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

// TestRootDNSKEYValidation checks root DNSKEY records against KSKs from root trust anchor.
func TestRootDNSKEYValidation(t *testing.T) {
	queriedDNSKEY, err := queryRoot(dns.TypeDNSKEY)
	if err != nil {
		t.Fatalf("Failed to query root DNSKEY records: %v", err)
	}

	KSKs := rootanchors.GetValidDNSKEYRecords()
	t.Logf("KSKs: %v", KSKs)

	var queriedKeys []dns.RR
	rrsigs := make(map[uint16]*dns.RRSIG)
	for _, rr := range queriedDNSKEY.Answer {
		if ns, ok := rr.(*dns.DNSKEY); ok {
			queriedKeys = append(queriedKeys, ns)
		} else if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigs[rrsig.TypeCovered] = rrsig
		} else {
			t.Fatalf("Unexpected RR type: %T", rr)
		}
	}

	rrsig, ok := rrsigs[dns.TypeDNSKEY]
	if !ok {
		t.Fatalf("RRSIG not found for DNSKEY records")
	}

	ksk, ok := KSKs[rrsig.KeyTag]
	if !ok {
		t.Fatalf("KSK not found for RRSIG with key tag %d", rrsig.KeyTag)
	}

	t.Logf("Verifying RRSet for RRSIG with key %v", ksk)
	if err := rrsig.Verify(ksk, queriedKeys); err != nil {
		t.Fatalf("Failed to verify RRSet: %v", err)
	}

	t.Logf("RRSet verified for RRSIG with key tag %d", rrsig.KeyTag)
}

// TestAnchorDNSKEYMatchesAnchorDSes checks that DNSKEY records from root trust anchor match DS records.
func TestAnchorDNSKEYMatchesAnchorDSes(t *testing.T) {
	dnsKeys := rootanchors.GetValidDNSKEYRecords()
	dsRecords := rootanchors.GetValidDSRecords()

	for keyTag, dnsKey := range dnsKeys {
		ds, ok := dsRecords[keyTag]
		if !ok {
			t.Fatalf("DS record not found for DNSKEY with key tag %d", keyTag)
		}

		computedDS := dnsKey.ToDS(ds.DigestType)
		computedDigest := strings.ToUpper(computedDS.Digest)
		t.Logf("Authentic digest: %s, computed digest: %s", ds.Digest, computedDigest)
		if computedDigest != ds.Digest {
			t.Fatalf("DS record mismatch for DNSKEY with key tag %d", keyTag)
		}
	}
}

// TestKSKAnchorsIncludesOnlineKSKs checks that the root trust anchor includes all online KSKs.
func TestKSKAnchorsIncludesOnlineKSKs(t *testing.T) {
	anchors := rootanchors.GetValidDNSKEYRecords()
	dnsKeys, err := queryRootKSK()
	if err != nil {
		t.Fatalf("Failed to query root DNSKEY records: %v", err)
	}

	for _, key := range dnsKeys {
		anchor, ok := anchors[key.KeyTag()]
		if !ok {
			t.Fatalf("KSK not found for DNSKEY with key tag %d", key.KeyTag())
		}

		if key.PublicKey != anchor.PublicKey {
			t.Fatalf("Public key mismatch for DNSKEY with key tag %d", key.KeyTag())
		}

		t.Logf("Public key matches for DNSKEY with key tag %d", key.KeyTag())
	}
}

// queryRoot queries the root zone (".") for the specified DNS record type.
func queryRoot(recordType uint16) (*dns.Msg, error) {
	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(".", recordType)
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, "198.41.0.4:53")
	if err != nil {
		return nil, fmt.Errorf("failed to query root: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("invalid answer for root query: %v", r.Rcode)
	}

	return r, nil
}

// queryRootKSK queries the KSK records for the root zone (".").
func queryRootKSK() ([]*dns.DNSKEY, error) {
	r, err := queryRoot(dns.TypeDNSKEY)
	if err != nil {
		return nil, err
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
