package cmd

import (
	"os"
	"path/filepath"

	"github.com/gogits/gogs/models"
	"github.com/gogits/gogs/modules/log"
	"github.com/gogits/gogs/modules/setting"
)

func setup(logPath string) {
	setting.NewConfigContext()
	log.NewGitLogger(filepath.Join(setting.LogRootPath, logPath))
	models.LoadModelsConfig()

	if models.UseSQLite3 {
		workDir, _ := setting.WorkDir()
		os.Chdir(workDir)
	}

	models.SetEngine()
}
