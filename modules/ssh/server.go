package ssh

import (
	"io"
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
	Stderr() io.Writer
}

type ConnectionInfo struct {
	Addr string
}

type ServerCallbackConfig struct {
	// The GetKeys callback is used to obtain a list of all keys that we should
	// accept connections from
	GetAllKeys func() [](string)

	// The HandleConnection function should execute "command path" (e.g.
	// git-upload-pack my/repo.git). The authentication of key is complete.
	// The communication should happen through the channel object.
	// The function returns the exit code of the command
	// If errors happen, they are optionally returned for logging
	HandleConnection func(key, cmd, repo string, channel *Channel, info ConnectionInfo) (int, error)
}

type Server interface {
	// Start server and return directly on successful start
	Start() error
	// Stop server and clean up (if necessary)
	Stop()

	// Notify server that key is now also acceptable
	AddKey(key string) error
	// Notify server that key is no longer valid
	RemoveKey(key string) error

	// Get all keytypes this server supports for clients
	KeyTypes() map[string]string

	// Get fingerprint of server
	Fingerprint() string

	// Handle the Gogs Serve command by validating it and passing it to the
	// callback
	//HandleGogsServeCommand() int
}
