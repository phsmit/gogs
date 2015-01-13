package ssh

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gogits/gogs/models"
	"github.com/gogits/gogs/modules/log"
	"github.com/gogits/gogs/modules/setting"
	"github.com/gogits/gogs/modules/ssh"
	"github.com/gogits/gogs/modules/uuid"
)

var permissionMap = map[string]models.AccessType{
	"git-upload-pack":    models.READABLE,
	"git-upload-archive": models.READABLE,
	"git-receive-pack":   models.WRITABLE,
}

func HandleConnection(fingerprint, cmd string, channel ssh.Channel, info ssh.ConnectionInfo) (uint32, error) {
	log.NewGitLogger(filepath.Join(setting.LogRootPath, "serv.log"))

	p, err := models.GetPublicKeyByFingerprint(fingerprint)
	if err != nil {
		return 1, err
	}

	user, err := models.GetUserById(p.OwnerId)
	if err != nil {
		return 1, err
	}

	parts := strings.SplitN(cmd, " ", 2)
	verb := parts[0]

	access, ok := permissionMap[verb]
	if !ok {
		fmt.Println(channel.Stderr(), "Gogs: Command not allowed", verb)
		log.GitLogger.Error(2, "Gogs: Command not allowed", verb)
		return 1, errors.New("Illegal verb")
	}

	args := parts[1]
	repoPath := strings.Trim(args, "'")
	rr := strings.SplitN(repoPath, "/", 2)
	if len(rr) != 2 {
		fmt.Println(channel.Stderr(), "Gogs: unavailable repository", args)
		log.GitLogger.Error(2, "Unavailable repository: %v", args)
		return 1, errors.New("Illegal args")
	}

	repoUserName := rr[0]
	repoName := strings.TrimSuffix(rr[1], ".git")

	repoUser, err := models.GetUserByName(repoUserName)
	if err != nil {
		fmt.Println(channel.Stderr(), "Gogs: unavailable repository", args)
		log.GitLogger.Error(2, "Unavailable repository: %v", args)
		return 1, errors.New("Illegal args")
	}

	repo, err := models.GetRepositoryByName(repoUser.Id, repoName)
	if err != nil {
		fmt.Println(channel.Stderr(), "Gogs: unavailable repository", args)
		log.GitLogger.Error(2, "Unavailable repository: %v", args)
		return 1, errors.New("Illegal args")
	}

	has, err := models.HasAccess(user.Name, path.Join(repoUserName, repoName), access)
	if err != nil {
		fmt.Println(channel.Stderr(), "Gogs: unavailable repository", args)
		log.GitLogger.Error(2, "Unavailable repository: %v", args)
		return 1, errors.New("Illegal args")
	}

	if !has && repo.IsPrivate {
		fmt.Println(channel.Stderr(), "Gogs: unavailable repository", args)
		log.GitLogger.Error(2, "Unavailable repository: %v", args)
		return 1, errors.New("Illegal args")
	}

	uuid := uuid.NewV4().String()
	os.Setenv("uuid", uuid)

	var gitcmd *exec.Cmd
	verbs := strings.Split(verb, " ")
	if len(verbs) == 2 {
		gitcmd = exec.Command(verbs[0], verbs[1], repoPath)
	} else {
		gitcmd = exec.Command(verb, repoPath)
	}
	gitcmd.Dir = setting.RepoRootPath
	gitcmd.Stdout = channel
	gitcmd.Stdin = channel
	gitcmd.Stderr = channel.Stderr()
	if err = gitcmd.Run(); err != nil {
		fmt.Println(channel.Stderr(), "Gogs: internal error:", err.Error())
		log.GitLogger.Error(2, "Fail to execute git command: %v", err)
		return 1, nil
	}

	if access == models.WRITABLE {
		tasks, err := models.GetUpdateTasksByUuid(uuid)
		if err != nil {
			log.GitLogger.Error(2, "GetUpdateTasksByUuid: %v", err)
			return 1, nil
		}

		for _, task := range tasks {
			err = models.Update(task.RefName, task.OldCommitId, task.NewCommitId,
				user.Name, repoUserName, repoName, user.Id)
			if err != nil {
				log.GitLogger.Error(2, "Fail to update: %v", err)
				return 1, nil
			}
		}

		if err = models.DelUpdateTasksByUuid(uuid); err != nil {
			log.GitLogger.Error(2, "DelUpdateTasksByUuid: %v", err)
			return 1, nil
		}
	}

	// Update key activity.
	key, err := models.GetPublicKeyById(p.Id)
	if err != nil {
		log.GitLogger.Error(2, "GetPublicKeyById: %v", err)
		return 1, nil
	}

	key.Updated = time.Now()
	if err = models.UpdatePublicKey(key); err != nil {
		log.GitLogger.Error(2, "UpdatePublicKey: %v", err)
		return 1, nil
	}

	return 0, nil
}
