package ssh

import "github.com/gogits/gogs/modules/ssh"

func HandleConnection(key, cmd string, channel ssh.Channel, info ssh.ConnectionInfo) (uint32, error) {
	return 0, nil
}
