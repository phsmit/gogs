// Copyright 2014 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cmd

import (
	"log"
	"os"

	"github.com/codegangsta/cli"
	"github.com/gogits/gogs/modules/ssh"
)

var CmdServ = cli.Command{
	Name:        "serv",
	Usage:       "This command should only be called by SSH shell",
	Description: `Serv provide access auth for repositories`,
	Action:      runServ,
	Flags:       []cli.Flag{},
}

func runServ(k *cli.Context) {

	if len(os.Args) < 5 {
		log.Fatal("Not enough arugments")
	}

	addr := os.Args[2]
	keyFile := os.Args[3]
	fingerprint := os.Args[4]

	client := ssh.GogsServeClient{
		InternalKeyFile: os.Args[3],
		Fingerprint:     os.Args[4],
		Host:            os.Args[2],
		Command:         os.Getenv("SSH_ORIGINAL_COMMAND"),
	}

	status, err := client.Run(os.Stdin, os.Stdout, os.Stderr)

	os.Exit(int(status))
}
