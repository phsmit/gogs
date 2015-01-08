package ssh

import (
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
	originalLines = []string{
		"# Comments allowed at start of line",
		"ssh-rsa AAAAB3Nza...LiPk== gogs@example.net",
		"from=\"*.sales.gogs.net,!pc.sales.example.net\" ssh-rsa AAAAB2...19Q== john@example.net",
		"command=\"dump /home\",no-pty,no-port-forwarding ssh-dss AAAAC3...51R== example.net",
		"permitopen=\"192.0.2.1:80\",permitopen=\"192.0.2.2:25\" ssh-dss AAAAB5...21S==",
		"tunnel=\"0\",command=\"sh /etc/netstart tun0\" ssh-rsa AAAA...== jane@example.net"}
)

func TestParseKey(t *testing.T) {

	s := Server{}

	for k, data := range testKeys {
		ok, key, fingerprint, keyType, size := s.parseTestKey([]byte(k))
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
	s := Server{}

	for k, data := range testKeys {
		ok, _, _, _, _ := s.parseTestKey([]byte("AAAAAQAA" + k))
		if ok {
			t.Errorf("Key (%s): should not be ok with fake packet prepended", data.keyType)
		}
	}
}

func TestParseKeyAppendRubbish(t *testing.T) {
	s := Server{}

	for k, data := range testKeys {
		ok, key, _, _, _ := s.parseTestKey([]byte(k + "\n-----"))
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
AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRb
YYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ
5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=
---- END SSH2 PUBLIC KEY ----`

	s := Server{}

	key, fingerprint, err := s.ParseKey(k)
	if err != nil {
		t.Error("SSH2 key not recognized")
		return
	}
	if key != "AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRbYYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=" {
		t.Error("SSH2 key not correct")
	}
	if fingerprint != "" {
		t.Error("SSH2 fingerprint not correct")
	}

}
