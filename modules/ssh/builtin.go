package ssh

//import (
//	"crypto"
//)

//type builtinServer struct {
//}

//func (*builtinServer) Start() error {
//	return nil
//}

//func (*builtinServer) Stop() {

//}

//func (*builtinServer) AddKey(key string) error {
//	return nil
//}
//func (*builtinServer) RemoveKey(key string) error {
//	return nil
//}
//func (*builtinServer) KeyTypes() map[string]string {
//	return nil
//}
//func (*builtinServer) Fingerprint() string {
//	return ""
//}

//// Configuration for creating an BuiltinServerConfig
//type BuiltinServerConfig struct {
//	Addr string
//	Key  crypto.PrivateKey
//}

//// The BuiltinServer is a full ssh-server that will listen by itself on
//// the specified ports for incoming git connections.
//func BuiltinServer(config BuiltinServerConfig, callbacks ServerCallbackConfig) Server {
//	return new(builtinServer)
//}
