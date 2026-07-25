package ldapserver

type HandleLogFn func(host string, f string, v ...interface{})

var HandleLogCallback HandleLogFn

func log(host string, f string, v ...interface{}) {
	if HandleLogCallback != nil {
		HandleLogCallback(host, f, v...)
	}
}
