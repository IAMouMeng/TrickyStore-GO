/*
Author: MouMeng
Mail: iamoumeng@aliyun.com
Date: 2026/4/25 09:49:20
*/

package config

import (
	"encoding/xml"
	"errors"
	"os"
	"strings"
)

type AndroidAttestation struct {
	XMLName          xml.Name `xml:"AndroidAttestation"`
	NumberOfKeyboxes int      `xml:"NumberOfKeyboxes"`
	Keyboxes         []Keybox `xml:"Keybox"`
}

type Keybox struct {
	DeviceID string `xml:"DeviceID,attr"`
	Key      Key    `xml:"Key"`
}

type Key struct {
	Algorithm        string           `xml:"algorithm,attr"`
	PrivateKey       PrivateKey       `xml:"PrivateKey"`
	CertificateChain CertificateChain `xml:"CertificateChain"`
}

type PrivateKey struct {
	Format string `xml:"format,attr"`
	Value  string `xml:",chardata"`
}

type CertificateChain struct {
	NumberOfCertificates int           `xml:"NumberOfCertificates"`
	Certificates         []Certificate `xml:"Certificate"`
}

type Certificate struct {
	Format string `xml:"format,attr"`
	Value  string `xml:",chardata"`
}

func CleanXMLPEM(s string) string {
	s = strings.ReplaceAll(s, "\r", "")

	s = strings.ReplaceAll(s, "\t", "")

	lines := strings.Split(s, "\n")

	var b strings.Builder
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	return strings.TrimSpace(b.String())
}

func Parse(path string) (*AndroidAttestation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg AndroidAttestation
	if err = xml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Keyboxes) == 0 {
		return nil, errors.New("could not find any keybox config")
	}

	for i := range cfg.Keyboxes {
		kb := &cfg.Keyboxes[i]

		kb.Key.PrivateKey.Value = CleanXMLPEM(kb.Key.PrivateKey.Value)

		for j := range kb.Key.CertificateChain.Certificates {
			kb.Key.CertificateChain.Certificates[j].Value =
				CleanXMLPEM(kb.Key.CertificateChain.Certificates[j].Value)
		}
	}

	return &cfg, nil
}
