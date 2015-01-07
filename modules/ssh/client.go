package ssh

import (
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"os"
)

type GogsServeClient struct {
	InternalKeyFile string
	Fingerprint     string
	Host            string
	Command         string
}

func (c *GogsServeClient) run() error {
	keyContents, err := ioutil.ReadFile(c.InternalKeyFile)
	if err != nil {
		return err
	}

	signer, err := ssh.ParsePrivateKey(keyContents)
	if err != nil {
		return err
	}

	sshConfig := &ssh.ClientConfig{
		User: "gogsproxy",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}

	client, err := ssh.Dial("tcp", c.Host, sshConfig)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}

	err = session.Start(c.Fingerprint + " info " + c.Command)
	if err != nil {
		return err
	}

	targetStderr, _ := session.StderrPipe()
	targetStdout, _ := session.StdoutPipe()
	targetStdin, _ := session.StdinPipe()

	go func() {
		io.Copy(targetStdin, os.Stdin)
	}()

	go func() {
		io.Copy(os.Stderr, targetStderr)
	}()

	go func() {
		io.Copy(os.Stdout, targetStdout)
	}()

	return session.Wait()
}
