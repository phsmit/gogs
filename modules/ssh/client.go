package ssh

import (
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
)

type GogsServeClient struct {
	InternalKeyFile string
	Fingerprint     string
	Host            string
	Command         string
}

func (c *GogsServeClient) Run(stdin io.Reader, stdout, stderr io.Writer) error {
	//log.Println("Run started now")
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

	//log.Println("Client dialled")

	session, err := client.NewSession()
	if err != nil {
		return err
	}

	targetStderr, _ := session.StderrPipe()
	targetStdout, _ := session.StdoutPipe()
	targetStdin, _ := session.StdinPipe()

	go func() {
		io.Copy(targetStdin, stdin)
		targetStdin.Close()
	}()

	go func() {
		io.Copy(stderr, targetStderr)
	}()

	go func() {
		io.Copy(stdout, targetStdout)
	}()

	err = session.Run(c.Fingerprint + " info " + c.Command)
	if err == io.EOF {
		return nil
	}
	return err
}
