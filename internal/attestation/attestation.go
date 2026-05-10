/*
Author: MouMeng
Mail: iamoumeng@aliyun.com
Date: 2026/4/22 11:11:28
*/

package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type SecurityLevel int

const (
	SecurityLevelSoftware           SecurityLevel = 0
	SecurityLevelTrustedEnvironment SecurityLevel = 1
	SecurityLevelStrongBox          SecurityLevel = 2
)

func (s SecurityLevel) String() string {
	switch s {
	case SecurityLevelSoftware:
		return "Software"
	case SecurityLevelTrustedEnvironment:
		return "TrustedEnvironment"
	case SecurityLevelStrongBox:
		return "StrongBox"
	default:
		return fmt.Sprintf("Unknown(%d)", int(s))
	}
}

type VerifiedBootState int

const (
	VerifiedBootStateVerified   VerifiedBootState = 0
	VerifiedBootStateSelfSigned VerifiedBootState = 1
	VerifiedBootStateUnverified VerifiedBootState = 2
	VerifiedBootStateFailed     VerifiedBootState = 3
)

func (v VerifiedBootState) String() string {
	switch v {
	case VerifiedBootStateVerified:
		return "Verified"
	case VerifiedBootStateSelfSigned:
		return "SelfSigned"
	case VerifiedBootStateUnverified:
		return "Unverified"
	case VerifiedBootStateFailed:
		return "Failed"
	default:
		return fmt.Sprintf("Unknown(%d)", int(v))
	}
}

type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState VerifiedBootState
	VerifiedBootHash  []byte
}

type AttestationPackageInfo struct {
	PackageName string
	Version     int64
}

type AttestationApplicationId struct {
	PackageInfos     []AttestationPackageInfo
	SignatureDigests [][]byte
}

type AuthorizationList struct {
	Purpose                     []int                     // [1]
	Algorithm                   *int                      // [2]
	KeySize                     *int                      // [3]
	Digest                      []int                     // [5]
	Padding                     []int                     // [6]
	EcCurve                     *int                      // [10]
	RsaPublicExponent           *int64                    // [200]
	RollbackResistance          bool                      // [303]
	ActiveDateTime              *int64                    // [400]
	OriginationExpireDateTime   *int64                    // [401]
	UsageExpireDateTime         *int64                    // [402]
	NoAuthRequired              bool                      // [503]
	UserAuthType                *int                      // [504]
	AuthTimeout                 *int                      // [505]
	AllowWhileOnBody            bool                      // [506]
	TrustedUserPresenceReq      bool                      // [507]
	TrustedConfirmationReq      bool                      // [508]
	UnlockedDeviceRequired      bool                      // [509]
	AllApplications             bool                      // [600]
	ApplicationId               []byte                    // [601]
	CreationDateTime            *int64                    // [701]
	Origin                      *int                      // [702]
	RollbackResistant           bool                      // [703]
	RootOfTrust                 *RootOfTrust              // [704]
	OsVersion                   *int                      // [705]
	OsPatchLevel                *int                      // [706]
	AttestationApplicationId    *AttestationApplicationId // [709]
	AttestationApplicationIdRaw []byte                    // [709] 原始字节
	AttestationIdBrand          []byte                    // [710]
	AttestationIdDevice         []byte                    // [711]
	AttestationIdProduct        []byte                    // [712]
	AttestationIdSerial         []byte                    // [713]
	AttestationIdImei           []byte                    // [714]
	AttestationIdMeid           []byte                    // [715]
	AttestationIdManufacturer   []byte                    // [716]
	AttestationIdModel          []byte                    // [717]
	VendorPatchLevel            *int                      // [718]
	BootPatchLevel              *int                      // [719]
}

type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel SecurityLevel
	KeymasterVersion         int
	KeymasterSecurityLevel   SecurityLevel
	AttestationChallenge     []byte
	UniqueId                 []byte
	SoftwareEnforced         AuthorizationList
	TeeEnforced              AuthorizationList
}

var attestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

func MarshalKeyDescription(kd *KeyDescription) ([]byte, error) {
	if kd == nil {
		return nil, fmt.Errorf("nil KeyDescription")
	}

	software, err := marshalAuthorizationList(kd.SoftwareEnforced)
	if err != nil {
		return nil, fmt.Errorf("marshal softwareEnforced: %w", err)
	}
	tee, err := marshalAuthorizationList(kd.TeeEnforced)
	if err != nil {
		return nil, fmt.Errorf("marshal teeEnforced: %w", err)
	}

	var body []byte
	appendField := func(v []byte, err error) error {
		if err != nil {
			return err
		}
		body = append(body, v...)
		return nil
	}

	if err := appendField(asn1.Marshal(kd.AttestationVersion)); err != nil {
		return nil, err
	}
	if err := appendField(asn1.Marshal(asn1.Enumerated(kd.AttestationSecurityLevel))); err != nil {
		return nil, err
	}
	if err := appendField(asn1.Marshal(kd.KeymasterVersion)); err != nil {
		return nil, err
	}
	if err := appendField(asn1.Marshal(asn1.Enumerated(kd.KeymasterSecurityLevel))); err != nil {
		return nil, err
	}
	if err := appendField(asn1.Marshal(kd.AttestationChallenge)); err != nil {
		return nil, err
	}
	if err := appendField(asn1.Marshal(kd.UniqueId)); err != nil {
		return nil, err
	}
	if err := appendField(software, nil); err != nil {
		return nil, err
	}
	if err := appendField(tee, nil); err != nil {
		return nil, err
	}

	return marshalSequence(body)
}

func BuildAttestationExtension(kd *KeyDescription, critical bool) (pkix.Extension, error) {
	der, err := MarshalKeyDescription(kd)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       attestationOID,
		Critical: critical,
		Value:    der,
	}, nil
}

func BuildExtensionsWithAttestation(cert *x509.Certificate, kd *KeyDescription) ([]pkix.Extension, error) {
	if cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}

	attestationExt, err := BuildAttestationExtension(kd, false)
	if err != nil {
		return nil, err
	}

	extensions := make([]pkix.Extension, 0, len(cert.Extensions)+1)
	replaced := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(attestationOID) {
			attestationExt.Critical = ext.Critical
			extensions = append(extensions, attestationExt)
			replaced = true
			continue
		}
		extensions = append(extensions, ext)
	}
	if !replaced {
		extensions = append(extensions, attestationExt)
	}
	return extensions, nil
}

func ReissueCertificateWithNewSignerKeepIdentity(template *x509.Certificate, signer crypto.PrivateKey, kd *KeyDescription) ([]byte, error) {
	if template == nil {
		return nil, fmt.Errorf("nil template certificate")
	}

	if signer == nil {
		return nil, fmt.Errorf("nil signer key")
	}

	extensions, err := BuildExtensionsWithAttestation(template, kd)
	if err != nil {
		return nil, err
	}

	cloned := *template
	cloned.ExtraExtensions = extensions
	cloned.SignatureAlgorithm = x509.UnknownSignatureAlgorithm

	parent := &x509.Certificate{
		Subject:    cloned.Issuer,
		RawSubject: cloned.RawIssuer,
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EC leaf key: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &cloned, parent, &leafKey.PublicKey, signer)

	if err != nil {
		return nil, fmt.Errorf("create certificate with new signer: %w", err)
	}
	return der, nil
}

func ParseCertificate(cert *x509.Certificate) (*KeyDescription, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(attestationOID) {
			return ParseKeyDescription(ext.Value)
		}
	}
	return nil, fmt.Errorf("attestation extension (OID %s) not found", attestationOID)
}

func ParseKeyDescription(data []byte) (*KeyDescription, error) {
	_, _, _, seqBody, _, err := parseTLV(data)
	if err != nil {
		return nil, fmt.Errorf("parse KeyDescription outer SEQUENCE: %w", err)
	}

	items, err := collectTLVs(seqBody)
	if err != nil {
		return nil, fmt.Errorf("parse KeyDescription fields: %w", err)
	}
	if len(items) < 8 {
		return nil, fmt.Errorf("KeyDescription has %d fields, expected at least 8", len(items))
	}

	kd := &KeyDescription{}

	kd.AttestationVersion, err = parseIntFromTLV(items[0])
	if err != nil {
		return nil, fmt.Errorf("attestationVersion: %w", err)
	}

	enumVal, err := parseIntFromTLV(items[1])
	if err != nil {
		return nil, fmt.Errorf("attestationSecurityLevel: %w", err)
	}
	kd.AttestationSecurityLevel = SecurityLevel(enumVal)

	kd.KeymasterVersion, err = parseIntFromTLV(items[2])
	if err != nil {
		return nil, fmt.Errorf("keymasterVersion: %w", err)
	}

	enumVal, err = parseIntFromTLV(items[3])
	if err != nil {
		return nil, fmt.Errorf("keymasterSecurityLevel: %w", err)
	}
	kd.KeymasterSecurityLevel = SecurityLevel(enumVal)

	kd.AttestationChallenge = items[4].value
	kd.UniqueId = items[5].value

	kd.SoftwareEnforced, err = parseAuthorizationList(items[6].value)
	if err != nil {
		return nil, fmt.Errorf("softwareEnforced: %w", err)
	}

	kd.TeeEnforced, err = parseAuthorizationList(items[7].value)
	if err != nil {
		return nil, fmt.Errorf("teeEnforced: %w", err)
	}

	return kd, nil
}

func parseAuthorizationList(data []byte) (AuthorizationList, error) {
	al := AuthorizationList{}
	items, err := collectTLVs(data)
	if err != nil {
		return al, err
	}

	for _, item := range items {
		if item.class != 2 {
			continue
		}
		switch item.tag {
		case 1:
			al.Purpose, err = parseIntSet(item.value)
		case 2:
			al.Algorithm, err = parseOptionalInt(item.value)
		case 3:
			al.KeySize, err = parseOptionalInt(item.value)
		case 5:
			al.Digest, err = parseIntSet(item.value)
		case 6:
			al.Padding, err = parseIntSet(item.value)
		case 10:
			al.EcCurve, err = parseOptionalInt(item.value)
		case 200:
			al.RsaPublicExponent, err = parseOptionalInt64(item.value)
		case 303:
			al.RollbackResistance = true
		case 400:
			al.ActiveDateTime, err = parseOptionalInt64(item.value)
		case 401:
			al.OriginationExpireDateTime, err = parseOptionalInt64(item.value)
		case 402:
			al.UsageExpireDateTime, err = parseOptionalInt64(item.value)
		case 503:
			al.NoAuthRequired = true
		case 504:
			al.UserAuthType, err = parseOptionalInt(item.value)
		case 505:
			al.AuthTimeout, err = parseOptionalInt(item.value)
		case 506:
			al.AllowWhileOnBody = true
		case 507:
			al.TrustedUserPresenceReq = true
		case 508:
			al.TrustedConfirmationReq = true
		case 509:
			al.UnlockedDeviceRequired = true
		case 600:
			al.AllApplications = true
		case 601:
			al.ApplicationId = extractOctetString(item.value)
		case 701:
			al.CreationDateTime, err = parseOptionalInt64(item.value)
		case 702:
			al.Origin, err = parseOptionalInt(item.value)
		case 703:
			al.RollbackResistant = true
		case 704:
			al.RootOfTrust, err = parseRootOfTrust(item.value)
		case 705:
			al.OsVersion, err = parseOptionalInt(item.value)
		case 706:
			al.OsPatchLevel, err = parseOptionalInt(item.value)
		case 709:
			raw := extractOctetString(item.value)
			al.AttestationApplicationIdRaw = raw
			al.AttestationApplicationId, _ = parseAttestationApplicationId(raw)
		case 710:
			al.AttestationIdBrand = extractOctetString(item.value)
		case 711:
			al.AttestationIdDevice = extractOctetString(item.value)
		case 712:
			al.AttestationIdProduct = extractOctetString(item.value)
		case 713:
			al.AttestationIdSerial = extractOctetString(item.value)
		case 714:
			al.AttestationIdImei = extractOctetString(item.value)
		case 715:
			al.AttestationIdMeid = extractOctetString(item.value)
		case 716:
			al.AttestationIdManufacturer = extractOctetString(item.value)
		case 717:
			al.AttestationIdModel = extractOctetString(item.value)
		case 718:
			al.VendorPatchLevel, err = parseOptionalInt(item.value)
		case 719:
			al.BootPatchLevel, err = parseOptionalInt(item.value)
		}
		if err != nil {
			return al, fmt.Errorf("tag %d: %w", item.tag, err)
		}
	}
	return al, nil
}

func parseRootOfTrust(data []byte) (*RootOfTrust, error) {
	_, _, _, seqBody, _, err := parseTLV(data)
	if err != nil {
		return nil, err
	}

	items, err := collectTLVs(seqBody)
	if err != nil {
		return nil, err
	}
	if len(items) < 3 {
		return nil, fmt.Errorf("RootOfTrust has %d fields, expected at least 3", len(items))
	}

	rot := &RootOfTrust{
		VerifiedBootKey: items[0].value,
	}

	if len(items[1].value) > 0 {
		rot.DeviceLocked = items[1].value[0] != 0
	}

	v, err := parseIntFromTLV(items[2])
	if err != nil {
		return nil, err
	}
	rot.VerifiedBootState = VerifiedBootState(v)

	if len(items) > 3 {
		rot.VerifiedBootHash = items[3].value
	}

	return rot, nil
}

func parseAttestationApplicationId(data []byte) (*AttestationApplicationId, error) {
	if len(data) == 0 {
		return nil, nil
	}
	_, _, _, seqBody, _, err := parseTLV(data)
	if err != nil {
		return nil, err
	}

	items, err := collectTLVs(seqBody)
	if err != nil {
		return nil, err
	}
	if len(items) < 2 {
		return nil, fmt.Errorf("AttestationApplicationId has %d fields, expected 2", len(items))
	}

	aaid := &AttestationApplicationId{}

	pkgItems, err := collectTLVs(items[0].value)
	if err != nil {
		return nil, err
	}
	for _, pi := range pkgItems {
		subItems, err := collectTLVs(pi.value)
		if err != nil {
			continue
		}
		if len(subItems) < 2 {
			continue
		}
		ver, _ := parseIntFromTLV(subItems[1])
		aaid.PackageInfos = append(aaid.PackageInfos, AttestationPackageInfo{
			PackageName: string(subItems[0].value),
			Version:     int64(ver),
		})
	}

	sigItems, err := collectTLVs(items[1].value)
	if err != nil {
		return nil, err
	}
	for _, si := range sigItems {
		aaid.SignatureDigests = append(aaid.SignatureDigests, si.value)
	}

	return aaid, nil
}

type tlvItem struct {
	class       int
	tag         int
	constructed bool
	value       []byte
	raw         []byte // 完整 TLV
}

func parseTLV(data []byte) (class, tag int, constructed bool, value, rest []byte, err error) {
	if len(data) == 0 {
		return 0, 0, false, nil, nil, fmt.Errorf("empty data")
	}
	start := 0
	pos := 0
	b := data[pos]
	pos++

	class = int(b >> 6)
	constructed = b&0x20 != 0
	tag = int(b & 0x1f)

	if tag == 0x1f {
		tag = 0
		for {
			if pos >= len(data) {
				return 0, 0, false, nil, nil, fmt.Errorf("truncated high tag at pos %d", pos)
			}
			b = data[pos]
			pos++
			tag = tag<<7 | int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}

	if pos >= len(data) {
		return 0, 0, false, nil, nil, fmt.Errorf("truncated length at pos %d", pos)
	}
	b = data[pos]
	pos++

	length := 0
	if b < 0x80 {
		length = int(b)
	} else if b == 0x80 {
		return 0, 0, false, nil, nil, fmt.Errorf("indefinite length not supported")
	} else {
		numBytes := int(b & 0x7f)
		for i := 0; i < numBytes; i++ {
			if pos >= len(data) {
				return 0, 0, false, nil, nil, fmt.Errorf("truncated length bytes")
			}
			length = length<<8 | int(data[pos])
			pos++
		}
	}

	if pos+length > len(data) {
		return 0, 0, false, nil, nil, fmt.Errorf("value truncated: need %d bytes at pos %d, have %d", length, pos, len(data)-pos)
	}
	_ = start
	return class, tag, constructed, data[pos : pos+length], data[pos+length:], nil
}

func collectTLVs(data []byte) ([]tlvItem, error) {
	var items []tlvItem
	for len(data) > 0 {
		cls, tag, cons, val, rest, err := parseTLV(data)
		if err != nil {
			return items, err
		}
		rawLen := len(data) - len(rest)
		items = append(items, tlvItem{
			class:       cls,
			tag:         tag,
			constructed: cons,
			value:       val,
			raw:         data[:rawLen],
		})
		data = rest
	}
	return items, nil
}

func parseIntFromTLV(item tlvItem) (int, error) {
	if item.constructed {
		_, _, _, inner, _, err := parseTLV(item.value)
		if err != nil {
			return 0, err
		}
		return bytesToInt(inner), nil
	}
	return bytesToInt(item.value), nil
}

func bytesToInt(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := new(big.Int)
	if b[0]&0x80 != 0 {
		notBytes := make([]byte, len(b))
		for i := range b {
			notBytes[i] = ^b[i]
		}
		n.SetBytes(notBytes)
		n.Add(n, big.NewInt(1))
		n.Neg(n)
	} else {
		n.SetBytes(b)
	}
	return int(n.Int64())
}

func bytesToInt64(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	n := new(big.Int)
	if b[0]&0x80 != 0 {
		notBytes := make([]byte, len(b))
		for i := range b {
			notBytes[i] = ^b[i]
		}
		n.SetBytes(notBytes)
		n.Add(n, big.NewInt(1))
		n.Neg(n)
	} else {
		n.SetBytes(b)
	}
	return n.Int64()
}

func parseOptionalInt(data []byte) (*int, error) {
	_, _, _, inner, _, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	v := bytesToInt(inner)
	return &v, nil
}

func parseOptionalInt64(data []byte) (*int64, error) {
	_, _, _, inner, _, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	v := bytesToInt64(inner)
	return &v, nil
}

func parseIntSet(data []byte) ([]int, error) {
	_, _, _, setBody, _, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	items, err := collectTLVs(setBody)
	if err != nil {
		return nil, err
	}
	var result []int
	for _, item := range items {
		result = append(result, bytesToInt(item.value))
	}
	return result, nil
}

func extractOctetString(data []byte) []byte {
	_, _, _, inner, _, err := parseTLV(data)
	if err != nil {
		return data
	}
	return inner
}

func marshalAuthorizationList(al AuthorizationList) ([]byte, error) {
	var body []byte
	addTag := func(tag int, inner []byte) error {
		raw, err := marshalContextExplicit(tag, inner)
		if err != nil {
			return err
		}
		body = append(body, raw...)
		return nil
	}
	addTagInt := func(tag int, v int) error {
		inner, err := asn1.Marshal(v)
		if err != nil {
			return err
		}
		return addTag(tag, inner)
	}
	addTagInt64 := func(tag int, v int64) error {
		inner, err := asn1.Marshal(v)
		if err != nil {
			return err
		}
		return addTag(tag, inner)
	}
	addTagNull := func(tag int) error {
		inner, err := asn1.Marshal(asn1.NullRawValue)
		if err != nil {
			return err
		}
		return addTag(tag, inner)
	}
	addTagOctets := func(tag int, v []byte) error {
		inner, err := asn1.Marshal(v)
		if err != nil {
			return err
		}
		return addTag(tag, inner)
	}
	addTagSetInts := func(tag int, values []int) error {
		inner, err := marshalIntSet(values)
		if err != nil {
			return err
		}
		return addTag(tag, inner)
	}

	if len(al.Purpose) > 0 {
		if err := addTagSetInts(1, al.Purpose); err != nil {
			return nil, err
		}
	}
	if al.Algorithm != nil {
		if err := addTagInt(2, *al.Algorithm); err != nil {
			return nil, err
		}
	}
	if al.KeySize != nil {
		if err := addTagInt(3, *al.KeySize); err != nil {
			return nil, err
		}
	}
	if len(al.Digest) > 0 {
		if err := addTagSetInts(5, al.Digest); err != nil {
			return nil, err
		}
	}
	if len(al.Padding) > 0 {
		if err := addTagSetInts(6, al.Padding); err != nil {
			return nil, err
		}
	}
	if al.EcCurve != nil {
		if err := addTagInt(10, *al.EcCurve); err != nil {
			return nil, err
		}
	}
	if al.RsaPublicExponent != nil {
		if err := addTagInt64(200, *al.RsaPublicExponent); err != nil {
			return nil, err
		}
	}
	if al.RollbackResistance {
		if err := addTagNull(303); err != nil {
			return nil, err
		}
	}
	if al.ActiveDateTime != nil {
		if err := addTagInt64(400, *al.ActiveDateTime); err != nil {
			return nil, err
		}
	}
	if al.OriginationExpireDateTime != nil {
		if err := addTagInt64(401, *al.OriginationExpireDateTime); err != nil {
			return nil, err
		}
	}
	if al.UsageExpireDateTime != nil {
		if err := addTagInt64(402, *al.UsageExpireDateTime); err != nil {
			return nil, err
		}
	}
	if al.NoAuthRequired {
		if err := addTagNull(503); err != nil {
			return nil, err
		}
	}
	if al.UserAuthType != nil {
		if err := addTagInt(504, *al.UserAuthType); err != nil {
			return nil, err
		}
	}
	if al.AuthTimeout != nil {
		if err := addTagInt(505, *al.AuthTimeout); err != nil {
			return nil, err
		}
	}
	if al.AllowWhileOnBody {
		if err := addTagNull(506); err != nil {
			return nil, err
		}
	}
	if al.TrustedUserPresenceReq {
		if err := addTagNull(507); err != nil {
			return nil, err
		}
	}
	if al.TrustedConfirmationReq {
		if err := addTagNull(508); err != nil {
			return nil, err
		}
	}
	if al.UnlockedDeviceRequired {
		if err := addTagNull(509); err != nil {
			return nil, err
		}
	}
	if al.AllApplications {
		if err := addTagNull(600); err != nil {
			return nil, err
		}
	}
	if len(al.ApplicationId) > 0 {
		if err := addTagOctets(601, al.ApplicationId); err != nil {
			return nil, err
		}
	}
	if al.CreationDateTime != nil {
		if err := addTagInt64(701, *al.CreationDateTime); err != nil {
			return nil, err
		}
	}
	if al.Origin != nil {
		if err := addTagInt(702, *al.Origin); err != nil {
			return nil, err
		}
	}
	if al.RollbackResistant {
		if err := addTagNull(703); err != nil {
			return nil, err
		}
	}
	if al.RootOfTrust != nil {
		rot, err := marshalRootOfTrust(*al.RootOfTrust)
		if err != nil {
			return nil, err
		}
		if err := addTag(704, rot); err != nil {
			return nil, err
		}
	}
	if al.OsVersion != nil {
		if err := addTagInt(705, *al.OsVersion); err != nil {
			return nil, err
		}
	}
	if al.OsPatchLevel != nil {
		if err := addTagInt(706, *al.OsPatchLevel); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationApplicationIdRaw) > 0 {
		if err := addTagOctets(709, al.AttestationApplicationIdRaw); err != nil {
			return nil, err
		}
	} else if al.AttestationApplicationId != nil {
		aaid, err := marshalAttestationApplicationId(*al.AttestationApplicationId)
		if err != nil {
			return nil, err
		}
		if err := addTagOctets(709, aaid); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdBrand) > 0 {
		if err := addTagOctets(710, al.AttestationIdBrand); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdDevice) > 0 {
		if err := addTagOctets(711, al.AttestationIdDevice); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdProduct) > 0 {
		if err := addTagOctets(712, al.AttestationIdProduct); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdSerial) > 0 {
		if err := addTagOctets(713, al.AttestationIdSerial); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdImei) > 0 {
		if err := addTagOctets(714, al.AttestationIdImei); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdMeid) > 0 {
		if err := addTagOctets(715, al.AttestationIdMeid); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdManufacturer) > 0 {
		if err := addTagOctets(716, al.AttestationIdManufacturer); err != nil {
			return nil, err
		}
	}
	if len(al.AttestationIdModel) > 0 {
		if err := addTagOctets(717, al.AttestationIdModel); err != nil {
			return nil, err
		}
	}
	if al.VendorPatchLevel != nil {
		if err := addTagInt(718, *al.VendorPatchLevel); err != nil {
			return nil, err
		}
	}
	if al.BootPatchLevel != nil {
		if err := addTagInt(719, *al.BootPatchLevel); err != nil {
			return nil, err
		}
	}

	return marshalSequence(body)
}

func marshalRootOfTrust(rot RootOfTrust) ([]byte, error) {
	var body []byte
	appendField := func(v []byte, err error) error {
		if err != nil {
			return err
		}
		body = append(body, v...)
		return nil
	}

	if err := appendField(asn1.Marshal(rot.VerifiedBootKey)); err != nil {
		return nil, err
	}
	if err := appendField(asn1.Marshal(rot.DeviceLocked)); err != nil {
		return nil, err
	}
	if err := appendField(asn1.Marshal(asn1.Enumerated(rot.VerifiedBootState))); err != nil {
		return nil, err
	}
	if len(rot.VerifiedBootHash) > 0 {
		if err := appendField(asn1.Marshal(rot.VerifiedBootHash)); err != nil {
			return nil, err
		}
	}
	return marshalSequence(body)
}

func marshalAttestationApplicationId(aaid AttestationApplicationId) ([]byte, error) {
	var pkgSet []byte
	for _, pkg := range aaid.PackageInfos {
		seq, err := asn1.Marshal(struct {
			PackageName string
			Version     int64
		}{
			PackageName: pkg.PackageName,
			Version:     pkg.Version,
		})
		if err != nil {
			return nil, err
		}
		pkgSet = append(pkgSet, seq...)
	}
	pkgSetRaw, err := asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      pkgSet,
	})
	if err != nil {
		return nil, err
	}

	var digestsSet []byte
	for _, digest := range aaid.SignatureDigests {
		raw, err := asn1.Marshal(digest)
		if err != nil {
			return nil, err
		}
		digestsSet = append(digestsSet, raw...)
	}
	digestsSetRaw, err := asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      digestsSet,
	})
	if err != nil {
		return nil, err
	}

	return marshalSequence(append(pkgSetRaw, digestsSetRaw...))
}

func marshalIntSet(values []int) ([]byte, error) {
	var body []byte
	for _, v := range values {
		raw, err := asn1.Marshal(v)
		if err != nil {
			return nil, err
		}
		body = append(body, raw...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      body,
	})
}

func marshalContextExplicit(tag int, inner []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      2,
		Tag:        tag,
		IsCompound: true,
		Bytes:      inner,
	})
}

func marshalSequence(body []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      body,
	})
}
