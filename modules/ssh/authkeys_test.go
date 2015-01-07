package ssh

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var (
	initialKeys = [3]string{
		"AAAAB3NzaC1kc3MAAACBALC/VdttgFR++b9ZhSVeqSren4nu+T0KYA/Eo4IagFbzlLf81ntL7APr52WsuWbJDxPug+tQsWEAVtMKVt8alQEfQuFqYYZzFCZ8Aog0WN/0mu6TdDzS6KblPfuKy3QYXNXcMMPyjx5Q6Fyh02sXL9dd7dAw+7z/jUgPCYTZDv+VAAAAFQD7v3w8+1JIUgA+3MVl5RqDFjLMrQAAAIBFntc2TkSMgcaBSWuKHx92WDgriBC0kFe0OK/Jlcw/8GPMt8PmO6RRxXHIbXpESBcl1tP/MCqQkpmBH/zPUfuKOwZJDm6RKYlxHo6W1nmAJZLLlh0CnIAwp775qLdR/FpILOYoYY8siEsq65a19vdz759bzSHfOduMMzDFXiQ5QwAAAIEAnCH4Z3uklutWl3gkLKMmNFNVmVA/qktyyBcMczX/pu0S47g4pRwv9dRTgfA4Wa+S9NT2WzvnU2e2zIKsXSfwWU3YkeV+ndy1e8xRc6uXIcNiEX7m1N/VqjyaThMV4VkVhbXQ0Sgf6tGay1f47NDn4xz6maxGLsc3XR9FJAgLbjs=",
		"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLV7JYV/YRalBUeqCDa+vphYfJ2bVjuh3c+U0L+bICgzPtGEGPGL69qSlrdLXIuZrwRRU5K7cAg9kXmNt4xBvDY=",
		"AAAAB3NzaC1yc2EAAAADAQABAAABAQCvjYnH4G9cVo45KjYILGkt5KNILth41aC378qdSmlyMhBsYseDnfx3y37gcbQRX7BqdWNkN3qWSX/84Ea2d4j2J74SkHZCqZfnL5CP4OT+Jq1U/O0lUspU3Fwe/b2ouxzLwTuGToZUBY340HK3C2YjyC5xMvAVcHwb63sP+/etvRa8luIqHWtdDV9VzQLO1X4Jlyg4cby39ceESEnetO1YAn8fsoz6hxSsmGV/Tb1exWlWqZkA8llFFuKwsnnt3iN+p0xMNWH7fRckoPy4v4OlaTmx5cSjF9AAphkhup1VWOmn7S9gSmBVPE+CI9/Vd8mXCrjip38XyGFGE6OEC9FZ"}
	testKeys = [2]string{
		"AAAAC3NzaC1lZDI1NTE5AAAAIMknEncBlSxLxebVndy6bVu1lbFyvAd8jymQ6SY1xJ7k",
		"AAAAC3NzaC1lZDI1NTE5AAAAIO/xPU/QQ9/DvtcTetmv76kLouWWFemF4VxadpovkXYC"}
	originalLines = [6]string{
		"# Comments allowed at start of line",
		"ssh-rsa AAAAB3Nza...LiPk== gogs@example.net",
		"from=\"*.sales.gogs.net,!pc.sales.example.net\" ssh-rsa AAAAB2...19Q== john@example.net",
		"command=\"dump /home\",no-pty,no-port-forwarding ssh-dss AAAAC3...51R== example.net",
		"permitopen=\"192.0.2.1:80\",permitopen=\"192.0.2.2:25\" ssh-dss AAAAB5...21S==",
		"tunnel=\"0\",command=\"sh /etc/netstart tun0\" ssh-rsa AAAA...== jane@example.net"}
)

func setupAuthkeyServer(authorizedContents string) (Server, *os.File) {
	f, err := ioutil.TempFile("", "testmainconf")
	f.Write([]byte(authorizedContents))
	if err != nil {
		panic(err)
	}

	server := AuthkeyServer{
		AuthorizedKeysFile: f.Name(),
		callbacks: ServerCallbackConfig{
			GetAllKeys: func() [](string) {
				return initialKeys[:]
			},
		},
	}

	return &server, f
}

func linesPresent(t *testing.T, lines []string, f string, expected bool) {
	for _, line := range lines {
		if strings.Contains(f, line) != expected {
			t.Errorf("Line \"%s\"; expected there: %t", line, expected)
		}
	}
}

func TestAuthorizedKeyFileReadWrite(t *testing.T) {
	s, f := setupAuthkeyServer(strings.Join(originalLines[:], "\n") + "\n")
	defer os.Remove(f.Name())

	c, _ := ioutil.ReadFile(f.Name())
	linesPresent(t, initialKeys[:], string(c), false)
	linesPresent(t, originalLines[:], string(c), true)

	if err := s.Start(); err != nil {
		panic(err)
	}

	c, _ = ioutil.ReadFile(f.Name())
	linesPresent(t, initialKeys[:], string(c), true)
	linesPresent(t, originalLines[:], string(c), true)
	linesPresent(t, testKeys[:], string(c), false)

	s.RemoveKey(initialKeys[0])

	c, _ = ioutil.ReadFile(f.Name())
	linesPresent(t, initialKeys[:1], string(c), false)
	linesPresent(t, initialKeys[1:], string(c), true)
	linesPresent(t, originalLines[:], string(c), true)

	for _, k := range testKeys {
		s.AddKey(k)
	}

	c, _ = ioutil.ReadFile(f.Name())
	linesPresent(t, initialKeys[:1], string(c), false)
	linesPresent(t, initialKeys[1:], string(c), true)
	linesPresent(t, originalLines[:], string(c), true)
	linesPresent(t, testKeys[:], string(c), true)

	s.Stop()

	c, _ = ioutil.ReadFile(f.Name())
	linesPresent(t, initialKeys[:], string(c), false)
	linesPresent(t, originalLines[:], string(c), true)
	linesPresent(t, testKeys[:], string(c), false)

}

func TestAddRemoveKey(t *testing.T) {

}
