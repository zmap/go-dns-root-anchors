package rootanchors

import (
	"encoding/xml"
	"time"

	"github.com/miekg/dns"
)

// https://data.iana.org/root-anchors/root-anchors.xml
// BEGIN IANA ROOT ANCHORS XML DATA
const IanaRootAnchorsXml = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="E9724F53-1851-4F86-85E5-F1392102940B" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
</KeyDigest>
<KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00">
<KeyTag>38696</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
</KeyDigest>
</TrustAnchor>`

// END XML DATA

// TrustAnchor represents the main XML structure.
type TrustAnchor struct {
	XMLName    xml.Name    `xml:"TrustAnchor"`
	ID         string      `xml:"id,attr"`
	Source     string      `xml:"source,attr"`
	Zone       string      `xml:"Zone"`
	KeyDigests []KeyDigest `xml:"KeyDigest"`
}

// KeyDigest represents the KeyDigest elements inside TrustAnchor.
type KeyDigest struct {
	ID         string `xml:"id,attr"`
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr,omitempty"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
}

// GetRawAnchors returns the raw XML data parsed into a TrustAnchor struct.
func GetRawAnchors() TrustAnchor {
	var ta TrustAnchor

	xml.Unmarshal([]byte(IanaRootAnchorsXml), &ta)

	return ta
}

// GetDSRecords returns root anchors as DS records defined by miekg/dns.
func GetValidDSRecords() map[uint16]dns.DS {
	ta := GetRawAnchors()

	dsRecords := make(map[uint16]dns.DS)
	for _, kd := range ta.KeyDigests {
		if !isKeyDigestValid(kd) {
			continue
		}

		dsRecords[kd.KeyTag] = dns.DS{
			Hdr:        dns.RR_Header{Name: ta.Zone},
			KeyTag:     kd.KeyTag,
			Algorithm:  kd.Algorithm,
			DigestType: kd.DigestType,
			Digest:     kd.Digest,
		}
	}

	return dsRecords
}

func isKeyDigestValid(kd KeyDigest) bool {
	validFrom, err := time.Parse(time.RFC3339, kd.ValidFrom)
	if err != nil {
		return false
	}

	if kd.ValidUntil == "" {
		return time.Now().After(validFrom)
	}

	validUntil, err := time.Parse(time.RFC3339, kd.ValidUntil)
	if err != nil {
		return false
	}

	return time.Now().After(validFrom) && time.Now().Before(validUntil)
}
