package ssh

import (
	"bytes"
	"crypto/md5"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"strings"
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

type Config struct {
	Host               string
	KeyFile            string
	AuthorizedKeyProxy AuthorizedKeysConfig
	Callbacks          CallbackConfig
}

type AuthorizedKeysConfig struct {
	Enabled            bool
	AuthorizedKeysFile string
	key                ssh.PublicKey
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

type Server interface {
	// Stop server and clean up (if necessary)
	Stop()

	// Notify server that key is now also acceptable
	AddKey(key string) error
	// Notify server that key is no longer valid
	RemoveKey(key string)

	// Ask the server to resync it's database (e.g. authorized keys file)
	Resync()

	// Get all keytypes this server supports for clients
	KeyTypes() map[string]string
}

// Create an SSH server, start it and return it
func NewServer(config Config) (Server, error) {
	s := &server{config: config}
	if err := s.start(); err != nil {
		return nil, err
	}
	return s, nil
}

type server struct {
	config Config
}

func handleChanReq(s *server, chanReq ssh.NewChannel, options map[string]string) {

	if chanReq.ChannelType() != "session" {
		chanReq.Reject(ssh.Prohibited, "channel type is not a session")
		return
	}

	ch, reqs, err := chanReq.Accept()
	if err != nil {
		log.Println("fail to accept channel request", err)
		return
	}
	defer ch.Close()

	req := <-reqs
	if req.Type != "exec" {
		ch.Write([]byte("request type '" + req.Type + "' is not 'exec'\r\n"))
		return
	}

	handleExec(s, ch, req, options)
}

// Payload: int: command size, string: command
func handleExec(s *server, ch ssh.Channel, req *ssh.Request, options map[string]string) {
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

		if key, err := s.config.Callbacks.GetKeyByFingerprint(fingerprint); err != nil {
			options["key"] = key
		}
	}

	key, has := options["key"]
	if !has {
		ch.Stderr().Write([]byte("Permission denied\n"))
		return
	}

	_, err := s.config.Callbacks.HandleConnection(key, command, ch, ConnectionInfo{})

	if err != nil {
		ch.Write([]byte(err.Error()))
		return
	}

	ch.Write([]byte("well done!\r\n"))

}

func (s *server) start() error {
	if s.config.Callbacks.GetAllKeys == nil || s.config.Callbacks.GetKeyByFingerprint == nil || s.config.Callbacks.HandleConnection == nil {
		return errors.New("All callbacks need to be not-nil")
	}

	config := ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.config.AuthorizedKeyProxy.Enabled {
				if bytes.Equal(key.Marshal(), s.config.AuthorizedKeyProxy.key.Marshal()) {
					return &ssh.Permissions{Extensions: map[string]string{"proxy": "y"}}, nil
				}
			}
			fingerprint := md5.Sum(key.Marshal())
			if k, err := s.config.Callbacks.GetKeyByFingerprint(fingerprint); err != nil {
				return &ssh.Permissions{Extensions: map[string]string{"key": k}}, nil
			} else {
				return nil, err
			}
		},
	}

	socket, err := net.Listen("tcp", s.config.Host)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := socket.Accept()
			if err != nil {
				continue
			}

			sshConn, newChans, _, err := ssh.NewServerConn(conn, &config)
			if err != nil {
				continue
			}
			defer sshConn.Close()

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

func (s *server) Stop() {

}

func (s *server) AddKey(key string) error {
	if s.config.AuthorizedKeyProxy.Enabled {
		// do something
	}
	return nil
}

func (s *server) RemoveKey(key string) {
	if s.config.AuthorizedKeyProxy.Enabled {
		// do something
	}
}

func (s *server) Resync() {

}

func (s *server) KeyTypes() map[string]string {
	return nil
}
