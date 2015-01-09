package ssh

import (
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
)

type GogsServeClient struct {
	InternalKeyFile string
	Fingerprint     string
	Host            string
	Command         string
}

func (c *GogsServeClient) Run(stdin io.Reader, stdout, stderr io.Writer) error {
	log.Println("Run started now")
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

	log.Println("Client dialled")

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	log.Println("Session created now")

	targetStderr, _ := session.StderrPipe()
	targetStdout, _ := session.StdoutPipe()
	targetStdin, _ := session.StdinPipe()

	log.Println("Session started now")

	go func() {
		io.Copy(targetStdin, stdin)
		targetStdin.Close()
		log.Println("Client: I'm done copying stdin")
	}()

	go func() {
		io.Copy(stderr, targetStderr)
		log.Println("Client: I'm done copying stderr")
	}()

	go func() {
		io.Copy(stdout, targetStdout)
		log.Println("Client: I'm done copying stdout")
	}()

	return session.Run(c.Fingerprint + " info " + c.Command)
	//if err != nil {
	//	return err
	//}

	//return session.Wait()
}
