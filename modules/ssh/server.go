package ssh

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	AuthorizedKeyProxy AuthorizedKeysConfig
	Callbacks          CallbackConfig
}

type AuthorizedKeysConfig struct {
	Enabled            bool
	AuthorizedKeysFile string

	m sync.Mutex
}

type CallbackConfig struct {
	// Return the content of a key with this fingerprint, or an error if this
	// fingerprint has no access
	GetKeyByFingerprint func(fingerprint [md5.Size]byte) (string, error)

	// The GetKeys callback is used to obtain a list of all keys that we should
	// accept connections from
	// Preferably return the keys in order of last used (most recently used first)
	GetAllKeys func() [](string)

	// The HandleConnection function should execute "command" (e.g.
	// git-upload-pack my/repo.git). The authentication of key is complete.
	// The communication should happen through the channel object.
	// The function returns the exit code of the command
	// If errors happen, they are optionally returned for logging
	HandleConnection func(key, cmd string, channel Channel, info ConnectionInfo) (int, error)
}

func handleChanReq(s *Server, chanReq ssh.NewChannel, options map[string]string) {

	if chanReq.ChannelType() != "session" {
		chanReq.Reject(ssh.Prohibited, "channel type is not a session")
		return
	}

	ch, reqs, err := chanReq.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	req := <-reqs
	if req.Type != "exec" {
		ch.Write([]byte("This server does not provide shell access"))
		return
	}

	handleExec(s, ch, req, options)
}

// Payload: int: command size, string: command
func handleExec(s *Server, ch ssh.Channel, req *ssh.Request, options map[string]string) {
	command := string(req.Payload[4:])

	if p, has := options["proxy"]; has && p == "y" {
		parts := strings.SplitN(command, " ", 3)
		if len(parts) != 3 {
			ch.Stderr().Write([]byte("Proxy error!\n"))
			return
		}

		command = parts[3]
		k, err := ssh.ParsePublicKey([]byte(parts[0]))
		if err != nil {
			ch.Stderr().Write([]byte("Proxy error!\n"))
			return
		}
		fingerprint := md5.Sum(k.Marshal())

		if key, err := s.Callbacks.GetKeyByFingerprint(fingerprint); err != nil {
			options["key"] = key
		}
	}

	key, has := options["key"]
	if !has {
		ch.Stderr().Write([]byte("Permission denied\n"))
		return
	}

	_, err := s.Callbacks.HandleConnection(key, command, ch, ConnectionInfo{})

	if err != nil {
		ch.Write([]byte(err.Error()))
		return
	}

	ch.Write([]byte("well done!\r\n"))

}

func (s *Server) Start() error {
	if s.Callbacks.GetAllKeys == nil || s.Callbacks.GetKeyByFingerprint == nil || s.Callbacks.HandleConnection == nil {
		return errors.New("All callbacks need to be not-nil")
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

	config := ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.AuthorizedKeyProxy.Enabled {
				if bytes.Equal(key.Marshal(), pubKey.Marshal()) {
					return &ssh.Permissions{Extensions: map[string]string{"proxy": "y"}}, nil
				}
			}
			fingerprint := md5.Sum(key.Marshal())
			if k, err := s.Callbacks.GetKeyByFingerprint(fingerprint); err != nil {
				return &ssh.Permissions{Extensions: map[string]string{"key": k}}, nil
			} else {
				return nil, err
			}
		},
	}

	config.AddHostKey(privKey)

	socket, err := net.Listen("tcp", s.Host)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := socket.Accept()
			if err != nil {
				continue
			}

			sshConn, newChans, requests, err := ssh.NewServerConn(conn, &config)
			if err != nil {
				continue
			}
			defer sshConn.Close()

			ssh.DiscardRequests(requests)

			//log.Println("Connection from", sshConn.RemoteAddr())
			go func() {
				for chanReq := range newChans {
					go handleChanReq(s, chanReq, sshConn.Permissions.Extensions)
				}
			}()
		}
	}()
	return nil
}

// Stop server and clean up (if necessary)
func (s *Server) Stop() {
	if s.AuthorizedKeyProxy.Enabled {
		s.AuthorizedKeyProxy.m.Lock()
		defer s.AuthorizedKeyProxy.m.Unlock()

		tmpFile := filepath.Join(filepath.Dir(s.AuthorizedKeyProxy.AuthorizedKeysFile), "authorized_keys.gogs.tmp")
		f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
		if err != nil {
			return
		}

		if origF, err := os.Open(s.AuthorizedKeyProxy.AuthorizedKeysFile); err == nil {
			r := bufio.NewReader(origF)
			for line, err := r.ReadBytes('\n'); err == nil; {
				if !bytes.Contains(line, []byte("gogs")) || !bytes.Contains(line, []byte("serve")) {
					f.Write(line)
				}
			}
			origF.Close()
		}
		f.Close()
		os.Rename(tmpFile, s.AuthorizedKeyProxy.AuthorizedKeysFile)
	}
}

// Notify server that key is now also acceptable
func (s *Server) AddKey(key string) error {
	if s.AuthorizedKeyProxy.Enabled {
		s.AuthorizedKeyProxy.m.Lock()
		defer s.AuthorizedKeyProxy.m.Unlock()

		tmpFile := filepath.Join(filepath.Dir(s.AuthorizedKeyProxy.AuthorizedKeysFile), "authorized_keys.gogs.tmp")
		f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
		if err != nil {
			return err
		}

		if pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err == nil {
			f.WriteString(fmt.Sprintf("command=\"\" %s %s\n", md5.Sum(pubKey.Marshal()), ssh.MarshalAuthorizedKey(pubKey)))
		}

		if origF, err := os.Open(s.AuthorizedKeyProxy.AuthorizedKeysFile); err == nil {
			io.Copy(f, origF)
		}
		f.Close()
		return os.Rename(tmpFile, s.AuthorizedKeyProxy.AuthorizedKeysFile)
	}
	return nil
}

// Notify server that key is no longer valid
func (s *Server) RemoveKey(key string) {
	if s.AuthorizedKeyProxy.Enabled {
		// do something
	}
}

// Ask the server to resync it's database (e.g. authorized keys file)
func (s *Server) Resync() error {
	if s.AuthorizedKeyProxy.Enabled {
		s.AuthorizedKeyProxy.m.Lock()
		defer s.AuthorizedKeyProxy.m.Unlock()

		tmpFile := filepath.Join(filepath.Dir(s.AuthorizedKeyProxy.AuthorizedKeysFile), "authorized_keys.gogs.tmp")
		f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
		if err != nil {
			return err
		}

		for _, key := range s.Callbacks.GetAllKeys() {
			if pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err == nil {
				f.WriteString(fmt.Sprintf("command=\"\" %s %s\n", md5.Sum(pubKey.Marshal()), ssh.MarshalAuthorizedKey(pubKey)))
			}
		}

		if origF, err := os.Open(s.AuthorizedKeyProxy.AuthorizedKeysFile); err == nil {
			r := bufio.NewReader(origF)
			for line, err := r.ReadBytes('\n'); err == nil; {
				if !bytes.Contains(line, []byte("gogs")) || !bytes.Contains(line, []byte("serve")) {
					f.Write(line)
				}
			}
			origF.Close()
		}
		f.Close()
		return os.Rename(tmpFile, s.AuthorizedKeyProxy.AuthorizedKeysFile)
	}
	return nil
}

// Get all keytypes this server supports for clients
func (s *Server) KeyTypes() map[string]string {
	return nil
}

func ValidateKey(content string) (string, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(content))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubKey.Marshal()), nil
}
