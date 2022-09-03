/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package geodb

import (
	"github.com/oschwald/geoip2-golang"
	"log"
)

type Client struct {
	logger    *log.Logger
	asnDB     *geoip2.Reader
	countryDB *geoip2.Reader
}
