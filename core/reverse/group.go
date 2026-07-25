/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type Unit struct {
	sync.Mutex
	reverse  *Reverse
	id       string
	group    *UnitGroup
	Callback func(*Event) error
	Data     any
}

type UnitGroup struct {
	id             string
	units          sync.Map
	callbackCalled int32
	expireAt       time.Time
}

type DomainInfo struct {
	Domain             string
	Ip                 string
	IsDomainNameServer bool
}

func (u *Unit) Fetch(id int64) error {
	u.reverse.groupUnitCallbackMap.Store(fmt.Sprintf("%s_%s", u.group.id, u.id), u)
	u.group.fetch(id)
	return nil
}

func (u *Unit) GetEncodedVisitURL() (string, error) {
	// 秘钥为xxxx，输入 {"group_id":"rsi0","unit_id":"mkzn"} 生成 /i/196830/rsi0/mkzn/
	// 秘钥为xxxx，输入 {"group_id":"b5zi","unit_id":"5czh"} 生成 /i/6c6952/b5zi/5czh/
	// 秘钥为xxxx，输入 {"group_id":"rsi0","unit_id":"mkzn"} 生成 /i/196830/rsi0/mkzn/
	visitURL := fmt.Sprintf("http://%s/i/%s/%s/%s/",
		u.reverse.config.GetAddr(),
		generateHashedToken(u.reverse.config.Token, u.group.id, u.id),
		u.group.id,
		u.id)

	return visitURL, nil
}

func (u *Unit) GetQueryDomain() (*DomainInfo, error) {
	// 秘钥为xxxx，输入{"group_id":"e0wk","unit_id":""}    生成 p-757bd4-e0wk.dnslog.com
	// "reverse/client config dns_server_ip is empty"
	di := DomainInfo{
		Domain: fmt.Sprintf("%s-%s-%s-%s.%s", "p", generateHashedToken(u.reverse.config.Token, u.group.id, u.id),
			u.group.id, u.id, u.reverse.config.DNSServerConfig.Domain),
		IsDomainNameServer: u.reverse.config.ClientConfig.DNSServerIP != "",
	}
	return &di, nil
}

func (u *Unit) GetRmiURL() string {
	rmiUrl := fmt.Sprintf("rmi://%s/i/%s/%s/%s/",
		u.reverse.config.GetAddr(),
		generateHashedToken(u.reverse.config.Token, u.group.id, u.id),
		u.group.id,
		u.id)
	return rmiUrl
}

func (u *Unit) GetLdapURL() string {
	ldapUrl := fmt.Sprintf("ldap://%s/i/%s/%s/%s/",
		u.reverse.config.GetAddr(),
		generateHashedToken(u.reverse.config.Token, u.group.id, u.id),
		u.group.id,
		u.id)
	return ldapUrl
}

func (u *Unit) GetVisitURL() string {
	// 秘钥为xxxx，输入 {"group_id":"rsi0","unit_id":"mkzn"} 生成 /i/196830/rsi0/mkzn/
	// 秘钥为xxxx，输入 {"group_id":"b5zi","unit_id":"5czh"} 生成 /i/6c6952/b5zi/5czh/
	visitURL := fmt.Sprintf("http://%s/i/%s/%s/%s/", u.reverse.config.GetAddr(),
		generateHashedToken(u.reverse.config.Token, u.group.id, u.id),
		u.group.id,
		u.id)
	return visitURL
}

func (u *Unit) OnVisit(f func(*Event) error) {
	u.Callback = f
}

func (ug *UnitGroup) Join(u *Unit) {
	ug.units.Store(u.id, u)
}

func (ug *UnitGroup) fetch(int64) error {
	ug.expireAt = time.Now().Add(2 * time.Minute)
	return nil
}

func (r *Reverse) gcExpiredGroup() {
	ticker := time.NewTicker(3 * time.Minute)
	for {
		select {
		case <-ticker.C:
			r.groupUnitCallbackMap.Range(func(key, value any) bool {
				if u, ok := value.(*Unit); ok {
					if time.Now().After(u.group.expireAt) {
						// logger.Infof("UnitCallback Expired be delete [%s/%s], expireAt %s", u.id, u.group.id, u.group.expireAt)
						r.groupUnitCallbackMap.Delete(key)
					}
				}
				return true
			})
		}
	}
	return
}

func (r *Reverse) gcExpiredEventMap() {
	ticker := time.NewTicker(3 * time.Minute)
	for {
		select {
		case <-ticker.C:
			count := 0
			r.internalGroupEventMap.Range(func(key, value any) bool {
				count++
				if count > 30 {
					return false
				}
				ev := value.(*Event)
				if time.Now().UnixMilli()-ev.TimeStamp > 3*60*1000 {
					logger.Infof("Event Expired be delete [%s/%s], %ds", ev.GroupID, ev.UnitID, (time.Now().UnixMilli()-ev.TimeStamp)/1000)
					r.internalGroupEventMap.Delete(key)
				}
				return true
			})
		}
	}
	ticker.Stop()
	return
}

func (r *Reverse) NewUnitGroup() *UnitGroup {
	return &UnitGroup{
		id:       utils.RandLowLetterNumber(4),
		expireAt: time.Now().Add(5 * time.Minute),
	}
}

func (r *Reverse) Register(data any) *Unit {
	group := r.NewUnitGroup()
	return r.RegisterWithGroup(data, group)
}

func (r *Reverse) RegisterWithGroup(data any, group *UnitGroup) *Unit {
	u := &Unit{
		id:      utils.RandLowLetterNumber(4),
		Data:    data,
		group:   group,
		reverse: r,
	}
	group.units.Store(u.id, u)
	return u
}

func generateHashedToken(token string, groupID string, unitID string) string {
	data := fmt.Sprintf("%s%s%s", token, groupID, unitID)
	return utils.Sha256([]byte(data))[0:6]
}

func parseDomainInfo(domain, mainDomain string) (hashedToken string, groupID string, unitID string, oobData string, err error) {
	i := strings.Index(domain, mainDomain)
	if i <= 0 {
		err = errors.New("不是我们指定的域名的子域名")
		return
	}
	pre := strings.Split(strings.Trim(domain[:i], "."), ".")
	if len(pre) == 2 {
		oobData = pre[1]
	}
	sid := pre[0]
	logger.Info(strings.Split(sid, "."), strings.Split(sid, "-"))
	fields := strings.Split(sid, "-")
	if len(fields) == 4 {
		hashedToken = fields[1]
		groupID = fields[2]
		unitID = fields[3]
	} else if len(fields) == 3 {
		hashedToken = fields[1]
		groupID = fields[2]
	} else {
		err = errors.New("不是我们指定的域名的子域名")
		return
	}
	return
}

func parseRmiURL(rawUrl string) (hashedToken string, groupID string, unitID string, oobData string, err error) {
	var u *url.URL
	u, err = url.Parse(rawUrl)
	if err != nil {
		return
	}

	fields := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(fields) == 6 {
		hashedToken = fields[2]
		groupID = fields[3]
		unitID = fields[4]
	}
	return
}

func parsePath(path string) (hashedToken string, groupID string, unitID string, oobData string, err error) {
	fields := strings.Split(strings.Trim(path, "/"), "/")
	if len(fields) == 6 {
		hashedToken = fields[2]
		groupID = fields[3]
		unitID = fields[4]
	} else if len(fields) == 4 {
		hashedToken = fields[1]
		groupID = fields[2]
		unitID = fields[3]
	}
	return
}

func parseVisitURL(rawUrl string) (hashedToken string, groupID string, unitID string, oobData string, err error) {
	var u *url.URL
	u, err = url.Parse(rawUrl)
	if err != nil {
		return
	}
	fields := strings.Split(strings.Trim(u.Path, "/"), "/")

	if len(fields) == 4 {
		hashedToken = fields[1]
		groupID = fields[2]
		unitID = fields[3]
	}
	return
}
