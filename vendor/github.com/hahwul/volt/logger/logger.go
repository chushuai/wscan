package logger

import (
	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
)

func GetLogger(debug bool) *logrus.Logger {
	log := logrus.New()
	log.SetFormatter(&nested.Formatter{
		HideKeys:    true,
		FieldsOrder: []string{"type", "data1", "data2", "data3", "data4"},
	})
	if debug {
		log.Level = logrus.DebugLevel
	}
	return log
}
