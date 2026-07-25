package logger

import (
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

var (
	Log      *logrus.Logger
	NfLog    *logrus.Entry
	MainLog  *logrus.Entry
	InitLog  *logrus.Entry
	CfgLog   *logrus.Entry
	CtxLog   *logrus.Entry
	GinLog   *logrus.Entry
	NgapLog  *logrus.Entry
	IKELog   *logrus.Entry
	GTPLog   *logrus.Entry
	NWuCPLog *logrus.Entry
	NWuUPLog *logrus.Entry
	RelayLog *logrus.Entry
	UtilLog  *logrus.Entry
)

func init() {
	fieldsOrder := []string{
		logger_util.FieldNF,
		logger_util.FieldCategory,
	}

	Log = logger_util.New(fieldsOrder)
	NfLog = Log.WithField(logger_util.FieldNF, "N3IWF")
	MainLog = NfLog.WithField(logger_util.FieldCategory, "Main")
	InitLog = NfLog.WithField(logger_util.FieldCategory, "Init")
	CfgLog = NfLog.WithField(logger_util.FieldCategory, "CFG")
	CtxLog = NfLog.WithField(logger_util.FieldCategory, "CTX")
	GinLog = NfLog.WithField(logger_util.FieldCategory, "GIN")
	NgapLog = NfLog.WithField(logger_util.FieldCategory, "NGAP")
	IKELog = NfLog.WithField(logger_util.FieldCategory, "IKE")
	GTPLog = NfLog.WithField(logger_util.FieldCategory, "GTP")
	NWuCPLog = NfLog.WithField(logger_util.FieldCategory, "NWuCP")
	NWuUPLog = NfLog.WithField(logger_util.FieldCategory, "NWuUP")
	RelayLog = NfLog.WithField(logger_util.FieldCategory, "Relay")
	UtilLog = NfLog.WithField(logger_util.FieldCategory, "Util")
}
