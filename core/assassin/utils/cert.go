/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"github.com/google/martian/mitm"
	"io/ioutil"
	"log"
	"path"
	"time"
)

func GenerateCA() ([]byte, []byte) {
	var err error
	//
	//	//CN = Insecure Root CA For X-Ray Scanner
	//	//OU = Service Infrastructure Department
	//	//O = Chaitin Tech
	//	//STREET = Beijing
	//	//L = Beijing
	//	//C = CN
	x509c, priv, err := mitm.NewAuthority("Insecure Root CA For Wscan Scanner", "Wscan Scanner", 365*10*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	crtBuff := bytes.NewBuffer(nil)
	keyBuff := bytes.NewBuffer(nil)
	pem.Encode(crtBuff, &pem.Block{Type: "CERTIFICATE", Bytes: x509c.Raw})
	pem.Encode(keyBuff, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return crtBuff.Bytes(), keyBuff.Bytes()
}

func GenerateCAToPath(filePath string) error {
	crtBuff, keyBuff := GenerateCA()
	ioutil.WriteFile(path.Join(filePath, "ca.crt"), crtBuff, 0777)
	ioutil.WriteFile(path.Join(filePath, "ca.key"), keyBuff, 0777)
	return nil
}
