package ssh

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const (
	KeyAlgoED25519 = "ssh-ed25519"
)

var (
	ErrNoKey                   = errors.New("No key found")
	ErrKeyTypeNotSupported     = errors.New("This keytype is not supported")
	ErrKeyTooSmall             = errors.New("The size of this key is too small")
	ErrFailedHostkeyGeneration = errors.New("Failed to generate host key")
)

var (
	ErrCallbacksAreNil = errors.New("All callbacks need to be not-nil")
)

var (
	internalKeyTypes = map[string]int{
		ssh.KeyAlgoDSA:      1024,
		ssh.KeyAlgoRSA:      2048,
		ssh.KeyAlgoECDSA256: 256,
		ssh.KeyAlgoECDSA384: 384,
		ssh.KeyAlgoECDSA521: 521,
	}
	otherKeyTypes = map[string]int{
		KeyAlgoED25519: 256,
	}
)

var (
	nonBase64 = regexp.MustCompile(`[^0-9a-zA-Z+=/\n\r]`)
)

type Channel interface {
	// Read reads up to len(data) bytes from the channel.
	// In the context of a process this would be stdin
	Read(data []byte) (int, error)
	// Write writes len(data) bytes to the channel.
	// In the context of a process this would be stdout
	Write(data []byte) (int, error)
	// Stderr returns an io.riter that writes to this channel
	// with the extended data type set to stderr. Stderr may
	// safely be written from a different goroutine than
	// Read and Write respectively.
	Stderr() io.ReadWriter
}

type ConnectionInfo struct {
	// Ip and port of connecting client
	Addr string
	// Is connecting through openssh proxy
	Proxied bool
}

type Server struct {
	Host               string
	KeyFile            string
	PubKeyFile         string
	pubKey             ssh.PublicKey
	keyTypes           map[string]int
	AuthorizedKeyProxy AuthorizedKeysConfig
	Callbacks          CallbackConfig

	socket net.Listener
}

type AuthorizedKeysConfig struct {
	Enabled            bool
	AuthorizedKeysFile string

	m sync.Mutex
}

type CallbackConfig struct {
	// Return the content of a key with this fingerprint, or an error if this
	// fingerprint has no access
	GetKeyByFingerprint func(fingerprint string) (string, error)

	// The GetKeys callback is used to obtain a list of all keys that we should
	// accept connections from
	// Preferably return the keys in order of last used (most recently used first)
	GetAllKeys func() [](string)

	// The HandleConnection function should execute "command" (e.g.
	// git-upload-pack my/repo.git). The authentication of key is complete.
	// The communication should happen through the channel object.
	// The function returns the exit code of the command
	// If errors happen, they are optionally returned for logging
	HandleConnection func(key, cmd string, channel Channel, info ConnectionInfo) (uint32, error)
}

func fingerprint(k ssh.PublicKey) string {
	m := md5.Sum(k.Marshal())
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15])
}

func handleChanReq(s *Server, chanReq ssh.NewChannel, options map[string]string) {
	log.Println("Handle chan req being called")
	if chanReq.ChannelType() != "session" {
		chanReq.Reject(ssh.Prohibited, "channel type is not a session")
		return
	}

	ch, reqs, err := chanReq.Accept()
	if err != nil {
		return
	}

	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			req.Reply(false, []byte{})
			continue
		} else {
			handleExec(s, ch, req, options)
			break
		}
	}

	log.Printf("Channel done and handled")

}

// Payload: int: command size, string: command
func handleExec(s *Server, ch ssh.Channel, req *ssh.Request, options map[string]string) {
	log.Printf("Exec being called %s", req.Payload)
	command := string(req.Payload[4:])

	if p, has := options["proxy"]; has && p == "y" {
		parts := strings.SplitN(command, " ", 3)
		log.Println("%d parts", len(parts))
		if len(parts) != 3 {
			ch.Stderr().Write([]byte("Proxy error!\n"))
			return
		}

		command = parts[2]
		f := string(parts[0])

		log.Println("I'm goint to check %s", f)
		if _, err := s.Callbacks.GetKeyByFingerprint(f); err == nil {
			options["fingerprint"] = f
		}
	}

	key, has := options["fingerprint"]
	if !has {
		ch.Stderr().Write([]byte("Permission denied\n"))
		return
	}

	exit_code, err := s.Callbacks.HandleConnection(key, command, ch, ConnectionInfo{})
	status := make([]byte, 4)
	binary.BigEndian.PutUint32(status, exit_code)
	ch.SendRequest("exit-status", false, status)

	if err != nil {
		ch.Write([]byte(err.Error()))
		return
	}
	log.Printf("Returning from handleExec")
}

func testKeytypeSshKeygen(keyType string) (bool, error) {
	tmpFile, err := ioutil.TempFile("", "keytest")
	if err != nil {
		return false, err
	}
	tmpFile.Close()
	tmpPath := tmpFile.Name()
	os.Remove(tmpPath)

	defer os.Remove(tmpPath)
	defer os.Remove(tmpPath + ".pub")

	log.Println("ssh-keygen", "-t", keyType, "-f", tmpPath, "-q", "-N", "")
	cmd := exec.Command("ssh-keygen", "-t", keyType, "-f", tmpPath, "-q", "-N", "")

	if out, err := cmd.CombinedOutput(); err != nil {
		log.Println(string(out))
		if bytes.HasPrefix(out, []byte("unknown key")) {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

func generateHostKey(keyFile, pubKeyFile string) error {
	return nil
}

// Start server
func (s *Server) Start() error {
	if s.Callbacks.GetAllKeys == nil || s.Callbacks.GetKeyByFingerprint == nil || s.Callbacks.HandleConnection == nil {
		return ErrCallbacksAreNil
	}

	if _, err := os.Stat(s.KeyFile); os.IsNotExist(err) {
		if err := generateHostKey(s.KeyFile, s.PubKeyFile); err != nil {
			return err
		}
	}

	pem, err := ioutil.ReadFile(s.KeyFile)
	if err != nil {
		return err
	}

	privKey, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return err
	}

	pubContent, err := ioutil.ReadFile(s.PubKeyFile)
	if err != nil {
		return err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubContent)
	if err != nil {
		return err
	}

	err = s.Resync()
	if err != nil {
		return err
	}

	log.Println("Before create config")
	config := ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.AuthorizedKeyProxy.Enabled {
				if bytes.Equal(key.Marshal(), pubKey.Marshal()) {
					return &ssh.Permissions{Extensions: map[string]string{"proxy": "y"}}, nil
				}
			}
			f := fingerprint(key)
			log.Printf("Validating key with fingerprint %s", f)
			if _, err := s.Callbacks.GetKeyByFingerprint(f); err != nil {
				return &ssh.Permissions{Extensions: map[string]string{}}, err
			} else {
				return &ssh.Permissions{Extensions: map[string]string{"fingerprint": f}}, nil
			}
		},
	}

	config.AddHostKey(privKey)

	log.Printf("Going to listen now")
	s.socket, err = net.Listen("tcp", s.Host)
	if err != nil {
		return err
	}
	log.Printf("server listening on %+v", s.socket.Addr())

	go func() {
		for {
			conn, err := s.socket.Accept()
			if err != nil {
				continue
			}
			log.Println("Incoming connection")

			sshConn, newChans, requests, err := ssh.NewServerConn(conn, &config)
			if err != nil {
				continue
			}
			defer sshConn.Close()

			log.Println("Upgraded to ssh")

			go ssh.DiscardRequests(requests)

			log.Println("Connection from", sshConn.RemoteAddr())
			go func() {
				for chanReq := range newChans {
					log.Printf("chan with permissions: %+v", sshConn.Permissions)
					go handleChanReq(s, chanReq, sshConn.Permissions.Extensions)
				}
			}()
		}
	}()

	if s.AuthorizedKeyProxy.Enabled {
		// discover key types from ssh-keygen
		s.keyTypes = map[string]int{}
		for k, v := range internalKeyTypes {
			// these keys are always supported, so don't need to be tested
			s.keyTypes[k] = v
		}
		for k, v := range otherKeyTypes {
			ok, err := testKeytypeSshKeygen(k)
			if ok {
				s.keyTypes[k] = v
			}
			if err != nil {
				return err
			}
		}
	} else {
		s.keyTypes = internalKeyTypes
	}
	return nil
}

// Stop server and clean up (if necessary)
func (s *Server) Stop() {
	s.socket.Close()
	if s.AuthorizedKeyProxy.Enabled {
		s.AuthorizedKeyProxy.writeAuthorizedKeyFile([]string{}, true)
	}
}

func (c *AuthorizedKeysConfig) writeAuthorizedKeyFile(newKeys []string, filterOld bool) error {
	c.m.Lock()
	defer c.m.Unlock()

	tmpFile := filepath.Join(filepath.Dir(c.AuthorizedKeysFile), "authorized_keys.gogs.tmp")
	f, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	for _, key := range newKeys {
		if ok, k, fingerprint, keyType, _ := parseKey([]byte(key), true); ok {
			f.WriteString(fmt.Sprintf("command=\"%s\" %s %s\n", fingerprint, keyType, k))
		}
	}

	if origF, err := os.Open(c.AuthorizedKeysFile); err == nil {
		if filterOld {
			r := bufio.NewReader(origF)
			for {
				line, err := r.ReadBytes('\n')

				if !bytes.Contains(line, []byte("gogs")) || !bytes.Contains(line, []byte("serve")) {
					f.Write(line)
				}

				if err != nil {
					break
				}
			}
		} else {
			io.Copy(f, origF)
		}
		origF.Close()
	}

	f.Close()
	return os.Rename(tmpFile, c.AuthorizedKeysFile)

}

// Notify server that key is now also acceptable
func (s *Server) AddKey(key string) error {
	if s.AuthorizedKeyProxy.Enabled {
		return s.AuthorizedKeyProxy.writeAuthorizedKeyFile([]string{key}, false)
	}
	return nil
}

// Notify server that key is no longer valid
func (s *Server) RemoveKey(key string) {
	// Removing one key is hard, let's go the easy way and regenerate the whole file
	// Alternatively we could do nothing, the key will be checked later again,
	// so it doesn't matter if it hangs around for a little bit
	s.Resync()
}

// Ask the server to resync it's database (e.g. authorized keys file)
func (s *Server) Resync() error {
	if s.AuthorizedKeyProxy.Enabled {
		return s.AuthorizedKeyProxy.writeAuthorizedKeyFile(s.Callbacks.GetAllKeys(), true)
	}
	return nil
}

// Get all keytypes this server supports for clients
func (s *Server) KeyTypes() map[string]int {
	return s.keyTypes
}

func parseKey(content []byte, clean bool) (ok bool, key string, fingerprint string, keyType string, size int) {
	if !clean {
		loc := nonBase64.FindIndex(content)
		if loc != nil {
			content = content[:loc[0]]
		}
	}
	raw := make([]byte, len(content)/4*3)
	n, _ := base64.StdEncoding.Decode(raw, content)
	//log.Printf("%d %x", n, raw[:n])

	if n > 0 {
		raw = raw[:n]
		key = base64.StdEncoding.EncodeToString(raw)
		h := md5.Sum(raw)
		fingerprint = hex.EncodeToString(h[:])
	} else {
		return
	}

	parts := make([][]byte, 0, 10)

	for len(raw) > 0 {
		if len(raw) < 4 {
			return
		}
		l := int(binary.BigEndian.Uint32(raw))
		raw = raw[4:]

		if len(raw) < l {
			return
		}
		parts = append(parts, raw[:l])
		raw = raw[l:]
	}

	if len(parts) < 2 {
		return
	}

	keyType = string(parts[0])

	switch keyType {
	case ssh.KeyAlgoRSA:
		if len(parts) != 3 {
			return
		}
		size = (len(parts[2]) - 1) * 8
	case ssh.KeyAlgoDSA:
		if len(parts) != 5 {
			return
		}
		size = (len(parts[1]) - 1) * 8
	case KeyAlgoED25519:
		if len(parts) != 2 {
			return
		}
		size = len(parts[1]) * 8
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		if len(parts) != 3 {
			return
		}
		size = internalKeyTypes[keyType]
	default:
		return
	}

	ok = true
	return
}

// Parse key from random content. On success return base64 key string. On failure
// return error
func (s *Server) ParseKey(content string) (string, string, error) {
	c := []byte(" " + content)

	for loc := 0; loc >= 0; loc = bytes.IndexAny(c, " \t\n\r\f") {
		c = c[loc+1:]
		ok, key, fingerprint, keyType, size := parseKey(c, false)
		if ok {
			minSize, has := s.keyTypes[keyType]
			if !has {
				return "", "", ErrKeyTypeNotSupported
			}

			if size < minSize {
				return "", "", ErrKeyTooSmall
			}
			return key, fingerprint, nil
		}
	}

	return "", "", ErrNoKey
}
