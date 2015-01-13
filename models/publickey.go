// Copyright 2014 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Unknwon/com"

	"github.com/gogits/gogs/modules/log"
	"github.com/gogits/gogs/modules/setting"

	"github.com/gogits/gogs/modules/ssh"
)

var appPath = ""

var (
	ErrKeyAlreadyExist = errors.New("Public key already exist")
	ErrKeyNotExist     = errors.New("Public key does not exist")
)

var (
	SshPath string // SSH directory.
)

// homeDir returns the home directory of current user.
func homeDir() string {
	home, err := com.HomeDir()
	if err != nil {
		log.Fatal(4, "Fail to get home directory: %v %s", err, setting.AppName)
	}
	return home

}

func init() {
	var err error

	// Determine and create .ssh path.
	SshPath = filepath.Join(homeDir(), ".ssh")
	if err = os.MkdirAll(SshPath, 0700); err != nil {
		log.Fatal(4, "fail to create SshPath(%s): %v\n", SshPath, err)
	}
}

// PublicKey represents a SSH key.
type PublicKey struct {
	Id                int64
	OwnerId           int64     `xorm:"UNIQUE(s) INDEX NOT NULL"`
	Name              string    `xorm:"UNIQUE(s) NOT NULL"`
	Fingerprint       string    `xorm:"INDEX NOT NULL"`
	Content           string    `xorm:"TEXT NOT NULL"`
	Created           time.Time `xorm:"CREATED"`
	Updated           time.Time
	HasRecentActivity bool `xorm:"-"`
	HasUsed           bool `xorm:"-"`
}

func ParseValidatePublicKeyString(content string) (string, string, error) {
	return ssh.Serv.ParseKey(content)
}

// AddPublicKey adds new public key to database and authorized_keys file.
func AddPublicKey(key *PublicKey) (err error) {
	has, err := x.Get(key)
	if err != nil {
		return err
	} else if has {
		return ErrKeyAlreadyExist
	}

	// Save SSH key.
	if _, err = x.Insert(key); err != nil {
		return err
	}

	ssh.Serv.AddKey(key.Content)

	return nil
}

// GetPublicKeyById returns public key by given ID.
func GetPublicKeyById(keyId int64) (*PublicKey, error) {
	key := new(PublicKey)
	has, err := x.Id(keyId).Get(key)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrKeyNotExist
	}
	return key, nil
}

// ListPublicKeys returns a list of public keys belongs to given user.
func ListPublicKeys(uid int64) ([]*PublicKey, error) {
	keys := make([]*PublicKey, 0, 5)
	err := x.Where("owner_id=?", uid).Find(&keys)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		key.HasUsed = key.Updated.After(key.Created)
		key.HasRecentActivity = key.Updated.Add(7 * 24 * time.Hour).After(time.Now())
	}
	return keys, nil
}

// UpdatePublicKey updates given public key.
func UpdatePublicKey(key *PublicKey) error {
	_, err := x.Id(key.Id).AllCols().Update(key)
	return err
}

// DeletePublicKey deletes SSH key information both in database and authorized_keys file.
func DeletePublicKey(key *PublicKey) error {
	has, err := x.Get(key)
	if err != nil {
		return err
	} else if !has {
		return ErrKeyNotExist
	}

	if _, err = x.Delete(key); err != nil {
		return err
	}

	ssh.Serv.RemoveKey(key.Content)
	return nil
}

func GetKeyContentByFingerprint(fingerprint string) (string, error) {
	key := PublicKey{Fingerprint: fingerprint}
	has, err := x.Get(&key)
	if err != nil {
		return "", err
	}
	if !has {
		return "", ssh.ErrPermissionDenied
	}

	return key.Content, nil
}

func GetAllKeyContents() [](string) {
	var keys []PublicKey

	if err := x.Desc("updated").Find(keys); err != nil {
		return []string{}
	}

	contents := make([]string, len(keys))
	for i, k := range keys {
		contents[i] = k.Content
	}

	return contents
}
