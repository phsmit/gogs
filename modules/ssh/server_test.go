package ssh

import (
	"bytes"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

type keyData struct {
	keyType     string
	size        int
	fingerprint string
}

var (
	testKeys = map[string]keyData{
		"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKDMeKhrQa+GPPOIksafnmlxcH401iCTN6UEPZayC0gnQM3cIuEX2y58EwyVHITfgbDndM4A/lZDLTQnxekiHmk=":                                                                                                                                                                                                                                                                                                                                                                                                                                                         keyData{"ecdsa-sha2-nistp256", 256, "25762f3b08a514b9addfb2f538f04ab3"},
		"AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBD66ur1JKLaUZZ1Ug/fbXbMlwd8YOwxLfcvrxAg+L73kJPkiPzXE0zkYycBBKRF0mH1P4OOzjzPXx4KNtKFrmR0Y5kFWPcbALcveNG/u3V1W5lql1c1r3ehL+6OOjQEq0w==":                                                                                                                                                                                                                                                                                                                                                                                                             keyData{"ecdsa-sha2-nistp384", 384, "a5c7d72891386264ceba65198c151c91"},
		"AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAErzKhOVCufSiP2xlQmIzvRHXD6t4JTl4JS0XPz9TInkcZqRi0Juz64FAzcurkC/8d0qGdvAQXfZ+wOPSYrXfEeNwCwQGlNYImpaTcqg3RQxKQPdZKAux0yq0ptkG8OULfieRATe648kiN5ZWSb3WGneRA3FkbFR/sxTosCD8XLMJQVBg==":                                                                                                                                                                                                                                                                                                                                                             keyData{"ecdsa-sha2-nistp521", 521, "0b2d537bb89102ee96996feaa3d40ebd"},
		"AAAAB3NzaC1kc3MAAACBAIj1YvMaQrHDEnDX7f7mBSctXyFuVXPEU04HXDUASi0oLmiQe1iTHf3BXX6pdAa3Mc8bZ30HwQ5kjyxSA8LascD/VAoznv1FolDee4wjGex4cGfvfn56hHG/uf4HQS3AzxnT+hBSDFkWm/AY+f8PQArhlGQfhpzgrzVxbtA2pFbHAAAAFQC+I3TjWrpmZv3zMJ+ZNuyZA68HHQAAAIAs3AWnA73BXh3BdgPRxrWzlOm98Kah7XgTKFUUO27KGWIgNYY1tP/NZRSA1yBwu1l7O3AY3knhyuNrEVbyReA+qxjbUrHQEOVxb3NFIsoSdKm7HrIjSUc3KvAT2dKXCx1dOyircuEnyhmkph+kgcYtaXwcvMysSk812sKcbkDulgAAAIAXa0LcU1LpAOejqrqdkb7COshigYQS8gxrePhPx3skt9k4nMJ3/dTOsL92LpEUIdixoeXvv8fjRrVhEu+eoJ9QSgRwcIE7WEIjmDRLV0VDJE4WCfOR3pmGHi18WC9CKTopowpV3SGtUGuzHZBUs4EbYWwxvZnOviddRR89igEAKg==": keyData{"ssh-dss", 1024, "49d343d538ca3a734b9f30069a44452e"},
		"AAAAC3NzaC1lZDI1NTE5AAAAIOw6e0L1FN9qMPrF1K6NiAZQlezvGwFsfPFVjUH/sdx0": keyData{"ssh-ed25519", 256, "49a5ef89c1ca23515fedaad4188125ea"},
		"AAAAB3NzaC1yc2EAAAADAQABAAABAQDTbuP29xhh2XpqNC5BsiOlf0njyiBYU0zm4CyLpVu3PktnCaCk/zztIIIQJNlg7xKsnEyBmhG+vy1IeD7raoBG55OHZsKdEwqEr6O+dmVEy/cghD0/X1AKLF0q/1offo3VgDyfHkINgnheUR8a7csRJLF3H0mdeWFFlIp0hO5E66NXvcH8xAeCbPfRqbe5v6zcHqVUASwvWFHeLIKCVtRJjsbklLOtleTeftFp7ML9CgpxIuYvUUOXd5Zvi7ZYoU/Ey5dYHnqQoRKqk9XcFn03+NiH2O7udtDW7F9ylPwueveIWAZ7RgL0DufJ0H0Iu/4N3d+6dCIBKNwKZGQj8u4B": keyData{"ssh-rsa", 2048, "bec0957f854e8153e28b80840f2efec5"},
	}
	originalLines = `# Comments allowed at start of line
ssh-rsa AAAAB3Nza...LiPk== gogs@example.net
from="*.sales.gogs.net,!pc.sales.example.net" ssh-rsa AAAAB2...19Q== john@example.net
command="dump /home",no-pty,no-port-forwarding ssh-dss AAAAC3...51R== example.net
permitopen="192.0.2.1:80",permitopen="192.0.2.2:25" ssh-dss AAAAB5...21S==
tunnel="0",command="sh /etc/netstart tun0" ssh-rsa AAAA...== jane@example.net`

	testHostKeys = [][]byte{[]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA027j9vcYYdl6ajQuQbIjpX9J48ogWFNM5uAsi6Vbtz5LZwmg
pP887SCCECTZYO8SrJxMgZoRvr8tSHg+62qARueTh2bCnRMKhK+jvnZlRMv3IIQ9
P19QCixdKv9aH36N1YA8nx5CDYJ4XlEfGu3LESSxdx9JnXlhRZSKdITuROujV73B
/MQHgmz30am3ub+s3B6lVAEsL1hR3iyCglbUSY7G5JSzrZXk3n7RaezC/QoKcSLm
L1FDl3eWb4u2WKFPxMuXWB56kKESqpPV3BZ9N/jYh9ju7nbQ1uxfcpT8Lnr3iFgG
e0YC9A7nydB9CLv+Dd3funQiASjcCmRkI/LuAQIDAQABAoIBAQCTFlnQvSVhLQJU
T+i+G0dhIqQsq7jEuW6OTvWuUGL1n4ilLbVsE4Q3Ep5ozLnNDYRYQIOYxa4CnMzL
1Zsv+u8yZHflgj9xNoXiuK2ZGpRov9wz6ssRAyWTbjmCaBIyRsA0/vktWMdqzpEe
TCDvgu36ByTOUh3MR1y8IxIO7Us09dPpdv1/N1it0x2JeHrapx7o5oCwz6lAcJCC
iKP9W48HVw4MOVHo7P+5vyGZ8gVDzzXUAUNE0I0u9tyHAKSrH7krpMzVm5RhKpUV
n7lSMmkX3rin+IBYu+GAt6ad5P0usSfmiNSfeaG1o647VKh9LXGYW86BfiT9Vyib
pgrEKSfhAoGBAPyOFYTcHo66rq4xDv1BY8N2Zic0GMEEwND+Is1VB2H8qQdbqlnU
a9CPxv6EvZT6ENhG8flfqKZJuIQs3hOW6R+p1OMAfMcHpz/QYkr30x249M2NccUJ
4D5WkYxpssKyf9SOhi37k+9mBg/1jsiJPZgGGifYARhWp0PjLtGt1HWDAoGBANZR
Nb489rujKDDCwT7gkA4kVNnPf7K5P3/emBFoyYPNjz8idMKt6ZIASzuknRqSyFvJ
qaytDHX006AKXUDDwtrT9NCsZMdF9fhnh8AQ+5J3vWFpcGpYrtyMhYwTGvEB5be1
T/a6dgLwPqK9MkaobXh1vmERreRF3J02n9yzujsrAoGACyAbNJIZyoHQxh2lImTq
BydFEr8JxB74e3xmfhMb0yY1L/zKwVBJO5PJ2VZxn4lwioZ9jFW5cTHYLgJn+gbw
2BM8LI/N71qX9Iiye8j1BN8r8Y4kj+CCf1yC5uOVG1yPowZwRMBLYQVmiPdxRcY9
7199cXnjenX+wk/UtSnqLQ8CgYBlNIxQfbF2AiIkhJOFAb6FLxrykE4ZM+mMlKzy
66zdlOCkS70fgcjerUzZqW6W8eGzlpONe1p7CVY2KS7IOql1dMoTEJW2lI8G8rzk
MiDalbjUm1n+nkpU0/bsoskCLocwLWrJdFvuH000xGtNepPXYqK4bATV2zfG9dif
/C9haQKBgQDTrCgH+kj6DGwrKhIF5mMJJy7c/gzOmqtVHxSH/0u21R+G66PyX61D
Q3LPhJ6J2ssj5x0ieM1faRFMRMPOkp7z9UqoBFkzrDzIq0pPO/wkknuQB3VxCf3w
IT/cTDo+BprdW6Lb3GEyJMZYnV9dUGIuowPD5+4T4Zec12TzsmMlkw==
-----END RSA PRIVATE KEY-----`),
		[]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu+x0DC3X3I0fL7c1nEmiQuOXjcpIua8UwLM+gYurnT3xLdy1
EhGhPayoO22P/Pvv93y3vFjCLK1idAKaTiyrxwnOQI9AHxvmu6oqjgPMxlc4h+ZE
1sqbEecLxpuxqdPZsxUNC70EJsEZRpcjevIuHCiXJ0V2ac1nOtqiTSa+6KqQ/6cP
dwi5ITQwl28j8VpAUSZGa8z24ZbFDt03SwddUVs9oL+qyUFK55EOJfx87DZDCXRa
4GOYccyYFP9LQbsaqYrkuhrCu+pEz2eBczhtv2ZEVe/hG2tZCjSWkTdTG6+knSJX
djnhmY2meDS1kqEpeSLP7kUZ3Vj2v5cxe/cOtwIDAQABAoIBACZOYa1l3t2PSq8g
SmZMQC4gVHFLrZ1kCffp0bD4dof762Cs36AKRfLbcgODJtmrxVOOcamL8jDHOw1o
xmlvA6jz374bNTfiKRtR6ZC/R4ualeRl1NxvukJg9W6LqCB1FahCf0FIS0NXEz7n
ag0StsF4qK8RoryYaRV/IZxWbI3idS8hsfQuxx1q8YzRL3IVebZ5KsmzS8njLQRW
ubIHz0gt0FYPuQU4l0yGs9wMQuEZsFkTWjCTamg+2wk22NaQYuaJf/gOHj+kRoOo
g1Mcl6yeyJD2ExvWIyeAXP14b6JGQKBl7+5zbQGgbwfhaeQwNbVGqKCT1W3atkiu
Bh6YIckCgYEA7VzVmxs7QZXf8V9et0c4pr/CmbQrP6Ex/ft1hL07Ig1I5WjdDW/s
6ZHpQdtjgTbp9uYwrWQngY1uWYuM8hncg+5NdYdFeAhYKtYsJGUGILHphn/7OScd
p89qN/bZibYDbCw9w/0ir/EUY57ssrSh3uJpr9fmNg9bmzvacueO+h0CgYEAyq3b
wzx+xwxaawfMH0J12EVGmWdHd6VJwm2v+uY50cEIT/sFpKuasujit5ma0wSab5z5
m29dW15MSHZJKm2ecOK/I8f1dfnyX7qCsF1cYyTH5UwpH5J4mUN2I2RlFfp+4eg1
9Jp3ROCwl3KngV7ZGeyf1PalmgNzubGbnYLxs+MCgYEAtaJCesydzZRIp8XZDtrb
SQ6YdVHffnN1c+tGhGrhoy8TRym1biDl494Z5qFhRXGmG58ORMDNUl/Nv4wAMQsF
KZfjgjofOLj57t2xLbB4vfAmyRuKPLPoB4+6slSdJro3aEF6ik1ci9IpTgpBCocb
Dxmm0j6eFWQvL1zfzunPCSkCgYBSeSSv8XH1NUWlv+qD3dtuQeJUkf425X96KoAt
rHlirRXg1diaBWpR2wpGg67Ip1rgiBPZ+BsZDuojol5rcWfDr8DvonJzq13BLnf3
pEXv4guldrRVMJj6ZMUx6axooSH4czFhc2mNEZFKT1FyB1J4hh0T37nLThRNP8R+
98W62QKBgHch+JiRrzi0amIEXmkTupjKo3kCEayLFOSRbtgTngBztiSMrj2/vbnr
cHB/hqoDJk70J5iBNjofcKuNe3qDRqWyR243hI/YuE5OASfrY6po9ZMCnLPDTNp/
iHwS2i1JFxnX9m+APOdCqPg0cAxi51rYjmPzXApJqy9MTFZT819W
-----END RSA PRIVATE KEY-----
`),
	}
	testPublicKeys = [][]byte{
		[]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTbuP29xhh2XpqNC5BsiOlf0njyiBYU0zm4CyLpVu3PktnCaCk/zztIIIQJNlg7xKsnEyBmhG+vy1IeD7raoBG55OHZsKdEwqEr6O+dmVEy/cghD0/X1AKLF0q/1offo3VgDyfHkINgnheUR8a7csRJLF3H0mdeWFFlIp0hO5E66NXvcH8xAeCbPfRqbe5v6zcHqVUASwvWFHeLIKCVtRJjsbklLOtleTeftFp7ML9CgpxIuYvUUOXd5Zvi7ZYoU/Ey5dYHnqQoRKqk9XcFn03+NiH2O7udtDW7F9ylPwueveIWAZ7RgL0DufJ0H0Iu/4N3d+6dCIBKNwKZGQj8u4B gogskey"),
		[]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC77HQMLdfcjR8vtzWcSaJC45eNyki5rxTAsz6Bi6udPfEt3LUSEaE9rKg7bY/8++/3fLe8WMIsrWJ0AppOLKvHCc5Aj0AfG+a7qiqOA8zGVziH5kTWypsR5wvGm7Gp09mzFQ0LvQQmwRlGlyN68i4cKJcnRXZpzWc62qJNJr7oqpD/pw93CLkhNDCXbyPxWkBRJkZrzPbhlsUO3TdLB11RWz2gv6rJQUrnkQ4l/HzsNkMJdFrgY5hxzJgU/0tBuxqpiuS6GsK76kTPZ4FzOG2/ZkRV7+Eba1kKNJaRN1Mbr6SdIld2OeGZjaZ4NLWSoSl5Is/uRRndWPa/lzF79w63 userkey")}

	testFingerprints = []string{
		"be:c0:95:7f:85:4e:81:53:e2:8b:80:84:0f:2e:fe:c5",
		"06:0f:6e:04:de:c7:f6:c1:5e:3b:19:f0:b6:7e:3f:69",
	}
)

func TestParseKey(t *testing.T) {
	for k, data := range testKeys {
		ok, key, fingerprint, keyType, size := parseKey([]byte(k), true)
		if !ok {
			t.Errorf("Key (%s): not recognized", data.keyType)
		}
		if k != key {
			t.Errorf("Key (%s): keys not equal", data.keyType)
		}
		if fingerprint != data.fingerprint {
			t.Errorf("Key (%s): Incorrect fingerprint", data.keyType)
		}
		if keyType != data.keyType {
			t.Errorf("Key (%s): Incorrect keytype", data.keyType)
		}
		if size != data.size {
			t.Errorf("Key (%s): Incorrect size", data.keyType)
		}
	}
}

func TestParseKeyPrependRubbish(t *testing.T) {
	for k, data := range testKeys {
		ok, _, _, _, _ := parseKey([]byte("AAAAAQAA"+k), true)
		if ok {
			t.Errorf("Key (%s): should not be ok with fake packet prepended", data.keyType)
		}
	}
}

func TestParseKeyAppendRubbish(t *testing.T) {
	for k, data := range testKeys {
		ok, key, _, _, _ := parseKey([]byte(k+"\n-----"), false)
		if !ok {
			t.Errorf("Key (%s): should be ok with rubbish appended", data.keyType)
		}
		if key != k {
			t.Errorf("Key (%s): should be equal with rubbish appended", data.keyType)
		}
	}

}

func TestParseKeySSH2(t *testing.T) {
	k := `---- BEGIN SSH2 PUBLIC KEY ----
Comment: "1024-bit RSA, converted from OpenSSH by me@example.com"
x-command: /home/me/bin/lock-in-guest.sh
AAAAB3NzaC1yc2EAAAADAQABAAABAQDTbuP29xhh2XpqNC5BsiOlf0njyiBYU0zm4CyL
pVu3PktnCaCk/zztIIIQJNlg7xKsnEyBmhG+vy1IeD7raoBG55OHZsKdEwqEr6O+dmVE
y/cghD0/X1AKLF0q/1offo3VgDyfHkINgnheUR8a7csRJLF3H0mdeWFFlIp0hO5E66NX
vcH8xAeCbPfRqbe5v6zcHqVUASwvWFHeLIKCVtRJjsbklLOtleTeftFp7ML9CgpxIuYv
UUOXd5Zvi7ZYoU/Ey5dYHnqQoRKqk9XcFn03+NiH2O7udtDW7F9ylPwueveIWAZ7RgL0
DufJ0H0Iu/4N3d+6dCIBKNwKZGQj8u4B
---- END SSH2 PUBLIC KEY ----`
	baseKey := "AAAAB3NzaC1yc2EAAAADAQABAAABAQDTbuP29xhh2XpqNC5BsiOlf0njyiBYU0zm4CyLpVu3PktnCaCk/zztIIIQJNlg7xKsnEyBmhG+vy1IeD7raoBG55OHZsKdEwqEr6O+dmVEy/cghD0/X1AKLF0q/1offo3VgDyfHkINgnheUR8a7csRJLF3H0mdeWFFlIp0hO5E66NXvcH8xAeCbPfRqbe5v6zcHqVUASwvWFHeLIKCVtRJjsbklLOtleTeftFp7ML9CgpxIuYvUUOXd5Zvi7ZYoU/Ey5dYHnqQoRKqk9XcFn03+NiH2O7udtDW7F9ylPwueveIWAZ7RgL0DufJ0H0Iu/4N3d+6dCIBKNwKZGQj8u4B"

	s := Server{}
	s.keyTypes = internalKeyTypes

	key, fingerprint, err := s.ParseKey(k)
	if err != nil {
		t.Errorf("SSH2 key not recognized: %+v", err)
		return
	}
	if key != baseKey {
		t.Error("SSH2 key not correct")
	}
	if fingerprint != "bec0957f854e8153e28b80840f2efec5" {
		t.Error("SSH2 fingerprint not correct")
	}
}

func TestParseKeyErrors(t *testing.T) {
	unsupportedKey := "AAAAC3NzaC1lZDI1NTE5AAAAIOw6e0L1FN9qMPrF1K6NiAZQlezvGwFsfPFVjUH/sdx0"
	tooSmalKey := "AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4cB6EzRhmwGObIa1lXt/XpHwLjjBt3CxBe2GItJ1RRIDqDd15+DGKbgn4fQXl5ZfqSwignQlY7dFt4L6F5YlvyGy/NH/+KG5UZjZvMvjeI9C2W2WWjKbYimKmbCs/SvSDgyeTLg7bKXOaIR0gPl/3gdjhpFJ1s9wVSnoZoFeoIQ=="
	s := Server{}
	s.keyTypes = internalKeyTypes

	_, _, err := s.ParseKey(unsupportedKey)
	if err == nil || err != ErrKeyTypeNotSupported {
		t.Errorf("Expected ErrKeyTypeNotSupported, got %+v", err)
	}

	_, _, err = s.ParseKey(tooSmalKey)
	if err == nil || err != ErrKeyTooSmall {
		t.Errorf("Expected ErrKeyTooSmall, got %+v", err)
	}

	_, _, err = s.ParseKey("")
	if err == nil || err != ErrNoKey {
		t.Errorf("Expected ErrNoKey, got %+v", err)
	}
}

func TestParseKeyInvalidKeys(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString
	invalids := []string{
		enc([]byte{0, 0, 0, 3, 's', 's', 'h', 0, 0, 0, 1, 'b'}),
		enc([]byte{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 0, 1, 'b'}),
		enc([]byte{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 0, 1, 'b'}),
		enc([]byte{0, 0, 0, 7, 's', 's', 'h', '-', 'd', 's', 's', 0, 0, 0, 1, 'b'}),
		enc([]byte{0, 0, 0, 19, 'e', 'c', 'd', 's', 'a', '-', 's', 'h', 'a', '2', '-', 'n', 'i', 's', 't', 'p', '2', '5', '6', 0, 0, 0, 1, 'b'}),
		enc([]byte{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 1, 'b', 0, 0, 0, 1, 'b'}),
		enc([]byte{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'}),
	}

	for _, k := range invalids {
		ok, _, _, _, _ := parseKey([]byte(k), true)
		if ok {
			t.Errorf("Key %s should not be accepted", k)
		}
	}
}

func checkFingerprint(fingerprint string) (string, error) {
	if fingerprint == testFingerprints[1] {
		return string(testPublicKeys[1]), nil
	}

	if fingerprint == testFingerprints[0] {
		return string(testPublicKeys[0]), nil
	}

	return "", errors.New("Not found")
}

func getAllTestKeys() [](string) {
	keys := make([]string, 0, len(testKeys))
	for k, _ := range testKeys {
		keys = append(keys, k)
	}
	return keys
}

func doNothingWithConnection(key, cmd string, channel Channel, info ConnectionInfo) (uint32, error) {
	channel.Stderr().Write([]byte(key))

	io.Copy(channel, channel)
	return 25, nil
}

func TestPlainServer(t *testing.T) {
	s := Server{}

	tmpDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(tmpDir)

	ioutil.WriteFile(tmpDir+"/hostkey", testHostKeys[0], 0600)
	ioutil.WriteFile(tmpDir+"/hostkey.pub", testPublicKeys[0], 0600)

	s = Server{Callbacks: CallbackConfig{GetKeyByFingerprint: checkFingerprint,
		GetAllKeys:       getAllTestKeys,
		HandleConnection: doNothingWithConnection},
		KeyFile:    tmpDir + "/hostkey",
		PubKeyFile: tmpDir + "/hostkey.pub",
	}

	err := s.Start()
	defer s.Stop()

	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	client := GogsServeClient{
		InternalKeyFile: tmpDir + "/hostkey",
		Fingerprint:     testFingerprints[1],
		Host:            s.socket.Addr().String(),
		Command:         "echo",
	}

	bufStdin := bytes.NewBufferString("Hi")
	bufStdout := &bytes.Buffer{}
	bufStderr := &bytes.Buffer{}
	if err = client.Run(bufStdin, bufStdout, bufStderr); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	if bufStdout.String() != "Hi" {
		t.Errorf("Incorrect data on stdout %+v", bufStdout.String())
	}
	if bufStderr.String() != testFingerprints[0] {
		t.Errorf("Incorrect data on stderr %+v", bufStderr.String())
	}

}

func TestAuthKeyServer(t *testing.T) {
	s := Server{}

	tmpDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(tmpDir)

	ioutil.WriteFile(tmpDir+"/hostkey", testHostKeys[0], 0600)
	ioutil.WriteFile(tmpDir+"/hostkey.pub", testPublicKeys[0], 0600)

	s = Server{Callbacks: CallbackConfig{GetKeyByFingerprint: checkFingerprint,
		GetAllKeys:       getAllTestKeys,
		HandleConnection: doNothingWithConnection},
		KeyFile:    tmpDir + "/hostkey",
		PubKeyFile: tmpDir + "/hostkey.pub",
		AuthorizedKeyProxy: AuthorizedKeysConfig{
			Enabled:            true,
			AuthorizedKeysFile: tmpDir + "/authorized_keys",
		},
	}

	if err := s.Start(); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	defer s.Stop()

	client := GogsServeClient{
		InternalKeyFile: tmpDir + "/hostkey",
		Fingerprint:     testFingerprints[1],
		Host:            s.socket.Addr().String(),
		Command:         "echo",
	}

	bufStdin := bytes.NewBufferString("Hi")
	bufStdout := &bytes.Buffer{}
	bufStderr := &bytes.Buffer{}
	if err := client.Run(bufStdin, bufStdout, bufStderr); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
	if bufStdout.String() != "Hi" {
		t.Errorf("Incorrect data on stdout %+v", bufStdout.String())
	}
	if bufStderr.String() != testFingerprints[1] {
		t.Errorf("Incorrect data on stderr %+v", bufStderr.String())
	}

}

func TestAuthorizedKeysWriting(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(tmpDir)

	ioutil.WriteFile(tmpDir+"/authkeys", []byte(originalLines), 0600)

	s := Server{Callbacks: CallbackConfig{GetAllKeys: getAllTestKeys},
		AuthorizedKeyProxy: AuthorizedKeysConfig{
			Enabled:            true,
			AuthorizedKeysFile: tmpDir + "/authkeys",
		},
	}

	for k, _ := range testKeys {
		s.AddKey(k)
	}

	newContents, err := ioutil.ReadFile(tmpDir + "/authkeys")
	if err != nil {
		t.Errorf("Unexpected reading error %+v", err)
	}

	if !bytes.HasSuffix(newContents, []byte(originalLines)) {
		t.Errorf("Original lines are not preserved in Authorized keys")
	}

	for k, _ := range testKeys {
		if !bytes.Contains(newContents, []byte(k)) {
			t.Errorf("%s line was not added to Authorized keys", k)
		}
	}

	testOption := func(s []string, o string) bool {
		for _, a := range s {
			if a == o {
				return true
			}
		}
		return false
	}
	_, _, options, _, err := ssh.ParseAuthorizedKey(newContents)
	if err != nil {
		t.Errorf("Authkeys file can't be parsed")
	}

	for _, opt := range []string{"no-port-forwarding", "no-X11-forwarding", "no-agent-forwarding", "no-pty"} {
		if !testOption(options, opt) {
			t.Errorf("Flag %s is not written in authkeys file!", opt)
		}
	}

	if err := s.Resync(); err != nil {
		t.Errorf("Unexpected error when resyncing %+v", err)
	}

	for k, _ := range testKeys {
		if !bytes.Contains(newContents, []byte(k)) {
			t.Errorf("%s line was not added to Authorized keys", k)
		}
	}

	if !bytes.HasSuffix(newContents, []byte(originalLines)) {
		t.Errorf("Original lines are not preserved in Authorized keys")
	}

	if err := s.AuthorizedKeyProxy.writeAuthorizedKeyFile([]string{}, true); err != nil {
		t.Errorf("Unexpected error when clearing authkeys %+v", err)
	}

	for k, _ := range testKeys {
		if !bytes.Contains(newContents, []byte(k)) {
			t.Errorf("%s line was not removed from Authorized keys", k)
		}
	}

	if !bytes.HasSuffix(newContents, []byte(originalLines)) {
		t.Errorf("Original lines are not preserved in Authorized keys")
	}
}

func TestPlainServerErrors(t *testing.T) {
	s := Server{}

	err := s.Start()

	if err != ErrCallbacksAreNil {
		t.Errorf("with no options, expected ErrCallbacksAreNil, got %+v", err)
	}

	tmpDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(tmpDir)

	ioutil.WriteFile(tmpDir+"/hostkey", testHostKeys[0], 0600)
	ioutil.WriteFile(tmpDir+"/hostkey.pub", testPublicKeys[0], 0600)

	s = Server{Callbacks: CallbackConfig{GetKeyByFingerprint: checkFingerprint,
		GetAllKeys:       getAllTestKeys,
		HandleConnection: doNothingWithConnection},
		KeyFile:    tmpDir + "/hostkey",
		PubKeyFile: tmpDir + "/hostkey.pub",
	}

	s2 := s
	if err := s.Start(); err != nil {
		t.Errorf("First server on port should start fine, got error %+v", err)
	}

	s2.Host = s.socket.Addr().String()
	if err := s2.Start(); err == nil {
		t.Errorf("Second server on port should fail")
	}

	s.Stop()

	if err := s2.Start(); err != nil {
		t.Errorf("Second server should start fine now, got error %+v", err)
	}

	s2.Stop()
}

func TestGenerateKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	tmpDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(tmpDir)

	err := generateHostKey(tmpDir+"/hostkey", tmpDir+"/hostkey.pub")
	if err != nil {
		t.Errorf("Unexpected error generating keys: %+v", err)
	}
}

func TestKeygen(t *testing.T) {
	ok, err := testKeytypeSshKeygen("ssh-rsa")
	if !ok {
		t.Errorf("ssh-rsa should be a valid keytype, but testKeytypeSshKeygen returns false")
	}
	if err != nil {
		t.Errorf("ssh-rsa should be a valid keytype, but testKeytypeSshKeygen returns error %+v", err)
	}

	ok, err = testKeytypeSshKeygen("ssh-fail")
	if ok {
		t.Errorf("ssh-fail should not be recognized by ssh-keygen as valid keytype, but testKeytypeSshKeygen returns true")
	}

}

func TestServerPermDenied(t *testing.T) {
	tmpDir, _ := ioutil.TempDir("", "")
	defer os.RemoveAll(tmpDir)

	ioutil.WriteFile(tmpDir+"/hostkey", testHostKeys[0], 0600)
	ioutil.WriteFile(tmpDir+"/hostkey.pub", testPublicKeys[0], 0600)

	s := Server{Callbacks: CallbackConfig{GetKeyByFingerprint: func(fingerprint string) (string, error) {
		return "", ErrPermissionDenied
	},
		GetAllKeys:       func() [](string) { return nil },
		HandleConnection: doNothingWithConnection},
		KeyFile:    tmpDir + "/hostkey",
		PubKeyFile: tmpDir + "/hostkey.pub"}

	if err := s.Start(); err != nil {
		t.Errorf("Server should start fine, got error %+v", err)
	}

	client := GogsServeClient{
		InternalKeyFile: tmpDir + "/hostkey",
		Fingerprint:     testFingerprints[1],
		Host:            s.socket.Addr().String(),
		Command:         "echo",
	}

	bufStdin := bytes.NewBufferString("Hi")
	bufStdout := &bytes.Buffer{}
	bufStderr := &bytes.Buffer{}
	if err := client.Run(bufStdin, bufStdout, bufStderr); err == nil {
		t.Errorf("Connections should have failed with permission denied, but it didn't")
	}

}
