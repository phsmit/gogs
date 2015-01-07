package ssh

//import (
//	"bytes"
//	"fmt"
//	"io/ioutil"
//	"os"
//	//"sync"
//)

//const (
//	_TPL_PUBLICK_KEY = `command="%s serv %s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s %s gogskey` + "\n"
//)

////type AuthkeyServer struct {
////	mutex            sync.Mutex
////	running          bool
////	originalContents []byte

////	Addr               string
////	AuthorizedKeysFile string
////	Command            string

////	callbacks ServerCallbackConfig
////}

//func (s *AuthkeyServer) Start() error {
//	s.mutex.Lock()
//	defer s.mutex.Unlock()

//	buf, err := ioutil.ReadFile(s.AuthorizedKeysFile)
//	if err != nil && !os.IsNotExist(err) {
//		return err
//	}
//	s.originalContents = buf

//	f, err := ioutil.TempFile("", "authkeyserver")
//	if err != nil {
//		return err
//	}

//	f.Write(s.originalContents)

//	if s.callbacks.GetAllKeys != nil {
//		for _, key := range s.callbacks.GetAllKeys() {
//			f.Write([]byte(fmt.Sprintf(_TPL_PUBLICK_KEY, "gogs", key, "ssh-rsa", key)))
//		}
//	}

//	f.Close()
//	if err = os.Rename(f.Name(), s.AuthorizedKeysFile); err != nil {
//		return err
//	}

//	return nil
//}

//func (s *AuthkeyServer) Stop() {
//	s.mutex.Lock()
//	defer s.mutex.Unlock()

//	f, err := ioutil.TempFile("", "authkeyserver")
//	if err != nil {
//		return
//	}

//	f.Write(s.originalContents)

//	f.Close()
//	os.Rename(f.Name(), s.AuthorizedKeysFile)

//}

//func (s *AuthkeyServer) AddKey(key string) error {
//	s.mutex.Lock()
//	defer s.mutex.Unlock()

//	f, err := os.OpenFile(s.AuthorizedKeysFile, os.O_RDWR|os.O_APPEND, 0600)
//	if err != nil {
//		return err
//	}

//	defer f.Close()

//	_, err = f.WriteString(fmt.Sprintf(_TPL_PUBLICK_KEY, "gogs", key, "ssh-rsa", key))

//	return err
//}
//func (s *AuthkeyServer) RemoveKey(key string) error {
//	s.mutex.Lock()
//	defer s.mutex.Unlock()

//	b := []byte(key)

//	curContents, err := ioutil.ReadFile(s.AuthorizedKeysFile)
//	if err != nil {
//		return err
//	}

//	f, err := ioutil.TempFile("", "authkeyserver")
//	if err != nil {
//		return err
//	}

//	for _, line := range bytes.Split(curContents, []byte("\n")) {
//		if !bytes.Contains(line, b) {
//			f.Write(b)
//			f.Write([]byte("\n"))
//		}
//	}

//	f.Close()
//	return os.Rename(f.Name(), s.AuthorizedKeysFile)
//}
//func (*AuthkeyServer) KeyTypes() map[string]string {
//	return nil
//}
//func (*AuthkeyServer) Fingerprint() string {
//	return ""
//}
