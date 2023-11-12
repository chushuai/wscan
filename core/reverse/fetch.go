/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
)

type fetchEventResponse struct {
	ResponseBase
	Event []*Event `json:"data"`
}

type remoteFetchEventRequest struct {
	GroupToDelete []string `json:"group_to_delete"`
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
