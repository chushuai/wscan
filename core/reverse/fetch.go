/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"wscan/core/http"
	logger "wscan/core/utils/log"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
)

type fetchEventResponse struct {
	ResponseBase
	Event []*Event `json:"data"`
}

type remoteFetchEventRequest struct {
	GroupToDelete []string `json:"group_to_delete"`
	GroupToSearch []string `json:"group_to_search"`
	UnitsToSearch []string `json:"units_to_search"`
}

type AuthChallenge struct {
	Source string `json:"source,omitempty"`
	Origin string `json:"origin"`
	Scheme string `json:"scheme"`
	Realm  string `json:"realm"`
}

type AuthChallengeResponse struct {
	Response string `json:"response"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type ContinueRequestParams struct {
	RequestID string               `json:"requestId"`
	URL       string               `json:"url,omitempty"`
	Method    string               `json:"method,omitempty"`
	PostData  string               `json:"postData,omitempty"`
	Headers   []*fetch.HeaderEntry `json:"headers,omitempty"`
}

type ContinueWithAuthParams struct {
	RequestID             string                       `json:"requestId"`
	AuthChallengeResponse *fetch.AuthChallengeResponse `json:"authChallengeResponse"`
}

type EnableParams struct {
	Patterns           []*fetch.RequestPattern `json:"patterns,omitempty"`
	HandleAuthRequests bool                    `json:"handleAuthRequests,omitempty"`
}

type EventAuthRequired struct {
	RequestID     string               `json:"requestId"`
	Request       *network.Request     `json:"request"`
	FrameID       string               `json:"frameId"`
	ResourceType  string               `json:"resourceType"`
	AuthChallenge *fetch.AuthChallenge `json:"authChallenge"`
}

type EventRequestPaused struct {
	RequestID           string               `json:"requestId"`
	Request             *network.Request     `json:"request"`
	FrameID             string               `json:"frameId"`
	ResourceType        string               `json:"resourceType"`
	ResponseErrorReason string               `json:"responseErrorReason,omitempty"`
	ResponseStatusCode  int64                `json:"responseStatusCode,omitempty"`
	ResponseHeaders     []*fetch.HeaderEntry `json:"responseHeaders,omitempty"`
	NetworkID           string               `json:"networkId,omitempty"`
}

type fGetResponseBodyReturns struct {
	Body          string `json:"body,omitempty"`
	Base64encoded bool   `json:"base64Encoded,omitempty"`
}

type HeaderEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RequestPattern struct {
	URLPattern   string `json:"urlPattern,omitempty"`
	ResourceType string `json:"resourceType,omitempty"`
	RequestStage string `json:"requestStage,omitempty"`
}

type TakeResponseBodyAsStreamReturns struct {
	Stream string `json:"stream,omitempty"`
}

func (r *Reverse) localCallUnitCallback() {
	// sync___ptr_Map__Load
	// sync___ptr_Map__LoadAndDelete
}

func TransferSynMapEntries(src *sync.Map, dst *sync.Map) {
	src.Range(func(key, value any) bool {
		// 直接从src加载值，并将其存储到dst中
		dst.Store(key, value)
		// 从src中删除键值对
		src.Delete(key)
		return true // 继续遍历
	})
}

func SplitKeyToGroupUnit(key string) (group string, unit string) {
	fields := strings.Split(key, "_")
	if len(fields) >= 2 {
		group = fields[0]
		unit = fields[1]
	}
	return
}

func (r *Reverse) localFetchEvent() (ret []*Event, err error) {
	r.groupUnitCallbackMap.Range(
		func(key, value any) bool {
			if u, ok := value.(*Unit); ok {
				ev, loaded := r.internalGroupEventMap.Load(u.group)
				if loaded {
					if u.Callback != nil {
						u.Callback(ev.(*Event))
					}
					r.groupUnitCallbackMap.Delete(key)
				}
			}
			return true
		})
	return
}

func (r *Reverse) remoteFetchEvent() error {

	//POST /_/api/fetch HTTP/1.1
	//Host: 127.0.0.1:88
	//User-Agent: Go-http-client/1.1
	//Content-Length: 68
	//Content-Type: application/json
	//X-Token: xxx
	//Accept-Encoding: gzip
	//
	//{"group_to_delete":[],"group_to_search":null,"units_to_search":null}HTTP/1.1 200 OK
	// {"code":0,"
	//data":[{"id":8,"group_id":"qwb5","unit_id":"h2v6","time_stamp":1702490308331,"event_source":"internal","event_type":"http","request":"GET /i/418f06/qwb5/h2v6/ HTTP/1.1\r\nHost: 127.0.0.1:88\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
	//*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en\r\nCache-Control: max-age=0\r\nConnection: keep-alive\r\nSec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"\r\nSec-Ch-Ua-Mobile: ?0\r\nSec-Ch-Ua-Platform: \"Windows\"\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n\r\n","remote_addr":"127.0.0.1:52112"}]}
	rfer := remoteFetchEventRequest{}

	r.groupUnitCallbackMap.Range(
		func(key, value any) bool {
			if u, ok := value.(*Unit); ok {
				if u.group.id != "" {
					rfer.GroupToSearch = append(rfer.GroupToSearch, u.group.id)
				}
			}
			return true
		})

	if len(rfer.GroupToSearch) == 0 {
		return nil
	}
	opt := &http.ClientOptions{
		ReadTimeout: 60,
		DialTimeout: 60,
	}
	client := http.NewClientWithOptions(opt)
	u, err := url.JoinPath(r.config.ClientConfig.HTTPBaseURL, "/_/api/fetch")
	if err != nil {
		logger.Fatal(err)
	}

	data, _ := json.Marshal(rfer)
	req, _ := http.NewRequest("POST", u, nil)
	req.WithJSONBody(bytes.NewReader(data))
	resp, err := client.DoRaw(req)
	if err != nil {
		logger.Error(err)
		return err
	}
	feb := fetchEventResponse{}
	if err := json.Unmarshal(resp.GetRawBody(), &feb); err == nil {
		for _, ev := range feb.Event {
			value, loaded := r.groupUnitCallbackMap.LoadAndDelete(fmt.Sprintf("%s_%s", ev.GroupID, ev.UnitID))
			if loaded {
				if u, ok := value.(*Unit); ok {
					if u.Callback != nil {
						u.Callback(ev)
					}
				}
			}
			logger.Infof("remoteFetchEvent %s/%s", ev.GroupID, ev.UnitID)
		}
	}
	return nil
}

func (r *Reverse) FetchEvent() {
	ticker := time.NewTicker(3 * time.Second)
	for {
		select {
		case <-ticker.C:
			if r.config.ClientConfig.RemoteServer {
				r.remoteFetchEvent()
			} else {
				r.localFetchEvent()
			}
		}

	}
	ticker.Stop()
	return
}

func (r *Reverse) FetchURLEvent(path string) bool {
	_, groupID, unitID, _, err := parsePath(path)
	if err != nil {
		logger.Fatal(err)
	}
	// logger.Info("FetchURLEvent: ", hashedToken, groupID, unitID, oobData)
	if !r.config.ClientConfig.RemoteServer {
		found := false

		ev, loaded := r.internalGroupEventMap.Load(groupID)
		if loaded {
			ev := ev.(*Event)
			if ev.GroupID == groupID && ev.UnitID == unitID {
				found = true
				return false
			}
		}

		return found
	} else {
		rfer := remoteFetchEventRequest{
			GroupToSearch: []string{groupID},
		}
		opt := &http.ClientOptions{
			ReadTimeout: 60,
			DialTimeout: 60,
		}
		client := http.NewClientWithOptions(opt)
		u, err := url.JoinPath(r.config.ClientConfig.HTTPBaseURL, "/_/api/fetch")
		if err != nil {
			logger.Fatal(err)
		}

		data, _ := json.Marshal(rfer)
		req, _ := http.NewRequest("POST", u, nil)
		req.WithJSONBody(bytes.NewReader(data))
		resp, err := client.DoRaw(req)
		if err != nil {
			logger.Error(err)
			return false
		}
		feb := fetchEventResponse{}
		if err := json.Unmarshal(resp.GetRawBody(), &feb); err == nil {
			if len(feb.Event) > 0 {
				return true
			}
		}
	}
	return false
}
