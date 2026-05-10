/*
Author: MouMeng
Mail: iamoumeng@aliyun.com
Date: 2026/4/21 21:38:19
*/

package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"keystore_service/internal/attestation"
	"keystore_service/internal/config"
	"keystore_service/internal/utils"
)

func HackLeafCert(data []byte) ([]byte, error) {
	//fmt.Println(hex.Dump(data))
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	fmt.Println(cert.Issuer)
	fmt.Println(cert.Subject)

	kd, err := attestation.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	//fmt.Println("==================================")
	//if rot := kd.SoftwareEnforced.RootOfTrust; rot != nil {
	//	fmt.Printf("VerifiedBootKey: %x\n", rot.VerifiedBootKey)
	//	fmt.Printf("DeviceLocked: %v\n", rot.DeviceLocked)
	//	fmt.Printf("VerifiedBootState: %s\n", rot.VerifiedBootState)
	//	rot.VerifiedBootKey = utils.Random32Bytes()
	//	rot.DeviceLocked = true
	//	rot.VerifiedBootState = 0
	//
	//	var verifiedBootHashStr string
	//	var verifiedBootHash []byte
	//
	//	verifiedBootHashStr, err = utils.GetProp(verifiedBootHashPropName)
	//	if err != nil {
	//		verifiedBootHash = utils.Random32Bytes()
	//		utils.SetProp(verifiedBootHashPropName, fmt.Sprintf("%x", verifiedBootHash))
	//	} else {
	//		decoded, err := hex.DecodeString(verifiedBootHashStr)
	//		if err != nil || len(decoded) != 32 {
	//			verifiedBootHash = utils.Random32Bytes()
	//			utils.SetProp(verifiedBootHashPropName, fmt.Sprintf("%x", verifiedBootHash))
	//		} else {
	//			verifiedBootHash = decoded
	//		}
	//	}
	//	rot.VerifiedBootHash = verifiedBootHash
	//}

	kd.AttestationSecurityLevel = 1
	kd.TeeEnforced = kd.SoftwareEnforced

	var verifiedBootHashStr string
	var verifiedBootHash []byte

	verifiedBootHashStr, err = utils.GetProp(verifiedBootHashPropName)
	if err != nil {
		verifiedBootHash = utils.Random32Bytes()
		utils.SetProp(verifiedBootHashPropName, fmt.Sprintf("%x", verifiedBootHash))
	} else {
		decoded, err := hex.DecodeString(verifiedBootHashStr)
		if err != nil || len(decoded) != 32 {
			verifiedBootHash = utils.Random32Bytes()
			utils.SetProp(verifiedBootHashPropName, fmt.Sprintf("%x", verifiedBootHash))
		} else {
			verifiedBootHash = decoded
		}
	}

	var (
		osVersion       = 120000
		osPatchLevel    = 202202
		otherPatchLevel = 20220201
		origin          = 0
		algorithm       = 3 // KM_ALGORITHM_EC
		keySize         = 256
		ecCurve         = 1 // KM_EC_CURVE_P_256
	)

	kd.TeeEnforced.OsVersion = &osVersion
	kd.TeeEnforced.OsPatchLevel = &osPatchLevel
	kd.TeeEnforced.VendorPatchLevel = &otherPatchLevel
	kd.TeeEnforced.BootPatchLevel = &otherPatchLevel
	kd.TeeEnforced.Origin = &origin
	kd.TeeEnforced.Purpose = []int{2}
	kd.TeeEnforced.Algorithm = &algorithm
	kd.TeeEnforced.KeySize = &keySize
	kd.TeeEnforced.Digest = []int{4}
	kd.TeeEnforced.EcCurve = &ecCurve
	kd.TeeEnforced.NoAuthRequired = true
	kd.TeeEnforced.RootOfTrust = &attestation.RootOfTrust{
		VerifiedBootKey:   utils.Random32Bytes(),
		DeviceLocked:      true,
		VerifiedBootState: 0,
		VerifiedBootHash:  verifiedBootHash,
	}

	kd.SoftwareEnforced = attestation.AuthorizationList{}

	//fmt.Println("Issuer:", cert.Issuer.String())
	//fmt.Println("CN:", cert.Issuer.CommonName)
	//fmt.Println("==================================")

	cfg, err := config.Parse(keyboxConfigDir)
	if err != nil {
		return nil, err
	}

	if cfg.Keyboxes[0].Key.CertificateChain.NumberOfCertificates > 0 && len(cfg.Keyboxes[0].Key.CertificateChain.Certificates) > 1 {
		block, _ := pem.Decode([]byte(cfg.Keyboxes[0].Key.CertificateChain.Certificates[0].Value))
		if block != nil {
			chainCertInfo, _ := x509.ParseCertificate(block.Bytes)
			if chainCertInfo != nil {
				cert.Subject = chainCertInfo.Issuer
				cert.RawSubject = chainCertInfo.RawIssuer
				cert.Issuer = chainCertInfo.Subject
				cert.RawIssuer = chainCertInfo.RawSubject
			}
		}
	}

	privateKey, err := parsePrivateKeyMust()
	if err != nil {
		return nil, err
	}

	//fmt.Println(cert.Issuer)

	newDer, err := attestation.ReissueCertificateWithNewSignerKeepIdentity(
		cert,
		privateKey,
		kd,
	)
	if err != nil {
		return nil, err
	}

	//newCert, err := x509.ParseCertificate(newDer)
	//if err != nil {
	//	return nil, err
	//}

	//fmt.Println("========== leaf certificate ==========")
	//fmt.Println(newCert.Subject)
	//fmt.Println(newCert.Issuer)

	//certA, err := x509.ParseCertificate(newDer)
	//if err != nil {
	//	return nil, err
	//}
	//
	//kdA, err := attestation.ParseCertificate(certA)
	//if err != nil {
	//	return nil, err
	//}
	//
	//fmt.Println("Edited ==================================")
	//if rot := kdA.SoftwareEnforced.RootOfTrust; rot != nil {
	//	fmt.Printf("VerifiedBootKey: %x\n", rot.VerifiedBootKey)
	//	fmt.Printf("DeviceLocked: %v\n", rot.DeviceLocked)
	//	fmt.Printf("VerifiedBootState: %s\n", rot.VerifiedBootState)
	//}
	//fmt.Println("Issuer:", certA.Issuer.String())
	//fmt.Println("CN:", certA.Issuer.CommonName)
	//
	//fmt.Println(hex.Dump(newDer))

	return newDer, err
}

func parsePrivateKeyMust() (crypto.PrivateKey, error) {
	cfg, err := config.Parse(keyboxConfigDir)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(cfg.Keyboxes[0].Key.PrivateKey.Value))

	//fmt.Println(cfg.Keyboxes[0].Key.PrivateKey.Value)

	if block == nil {
		return nil, errors.New("invalid private key pem")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("parse RSA private key: %v", err))
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("parse PKCS8 private key: %v", err))
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("parse EC private key: %v", err))
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unknown private key type: %s", block.Type)
	}
}
func HackCertChain(data []byte) ([]byte, error) {
	//originCerts, err := x509.ParseCertificates(data)
	//if err != nil {
	//	return nil, err
	//}

	//for i, c := range originCerts {
	//	fmt.Println("====== Cert", i, "======")
	//	//fmt.Println("Subject:", c.Subject.CommonName)
	//	//fmt.Println("Issuer :", c.Issuer.CommonName)
	//	fmt.Println(c.Subject)
	//	fmt.Println(c.Issuer)
	//	fmt.Println()
	//}

	cfg, err := config.Parse(keyboxConfigDir)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	for i := range cfg.Keyboxes[0].Key.CertificateChain.NumberOfCertificates {
		block, _ := pem.Decode([]byte(cfg.Keyboxes[0].Key.CertificateChain.Certificates[i].Value))
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		//fmt.Println("====== Cert", i, "======")
		//fmt.Println("Subject:", c.Subject.CommonName)
		//fmt.Println("Issuer :", c.Issuer.CommonName)
		//fmt.Println(cert.Subject)
		//fmt.Println(cert.Issuer)
		//fmt.Println()
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no available certificates found")
	}

	var chainBytes []byte
	for _, cert := range certs {
		chainBytes = append(chainBytes, cert.Raw...)
	}

	return chainBytes, err
}
