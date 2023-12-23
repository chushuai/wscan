/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

type ClientConfig struct {
	RemoteServer  bool   `json:"remote_server" yaml:"remote_server" #:"是否是独立的远程 server，如果是要在下面配置好远程的服务端地址"`
	HTTPBaseURL   string `json:"http_base_url" yaml:"http_base_url" #:"默认将根据 ListenIP 和 ListenPort 生成，该地址是存在漏洞的目标反连回来的地址, 当反连平台前面有反代、绑定域名、端口映射时需要自行配置"`
	DNSServerIP   string `json:"dns_server_ip" yaml:"dns_server_ip" #:"和 http_base_url 类似，实际用来访问 dns 服务器的地址"`
	RMIServerAddr string `json:"rmi_server_addr" yaml:"rmi_server_addr" #:"和 http_base_url 类似，实际用来访问 rmi 服务的地址"`
}

type Config struct {
	DBFilePath       string           `json:"db_file_path" yaml:"db_file_path" #:"反连平台数据库文件位置, 这是一个 KV 数据库"`
	Token            string           `json:"token" yaml:"token" #:"反连平台认证的 Token, 独立部署时不能为空"`
	HTTPServerConfig HTTPServerConfig `json:"http" yaml:"http"`
	DNSServerConfig  DNSServerConfig  `json:"dns" yaml:"dns"`
	RMIServerConfig  RMIServerConfig  `json:"rmi" yaml:"rmi"`
	ClientConfig     ClientConfig     `json:"client" yaml:"client"`
}

type CommonResponseComponent struct {
	StatusCode string              `json:"statusCode"`
	Header     []map[string]string `json:"header"`
	Body       string              `json:"body"`
}

type DNSResponseConfig struct {
	GroupID     string `json:"groupID"`
	DNSResponse struct {
		A    []DNSResponseItem "json:\"a\""
		AAAA []DNSResponseItem "json:\"aaaa\""
		TXT  []DNSResponseItem "json:\"txt\""
	} `json:"dnsResponse"`
	DNSResponseIdx struct {
		A    uint32
		AAAA uint32
		TXT  uint32
	} `json:"dnsResponseIdx"`
}

type DNSResponseItem struct {
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type DNSServerConfig struct {
	Enabled            bool            `json:"enabled" yaml:"enabled"`
	ListenIP           string          `json:"listen_ip" yaml:"listen_ip"`
	Domain             string          `json:"domain" yaml:"domain" #:"DNS 域名配置"`
	IsDomainNameServer bool            `json:"is_domain_name_server" yaml:"is_domain_name_server" #:"是否修改了域名的 ns 为反连平台，如果是，那 nslookup 等就不需要指定 dns 了"`
	Resolve            []ResolveConfig `json:"resolve" yaml:"resolve" #:"DNS 静态解析规则"`
}

type DomainInfo struct {
	Domain             string
	Ip                 string
	IsDomainNameServer bool
}

type Event struct {
	ID          int64  `json:"id"`
	GroupID     string `json:"group_id"`
	UnitId      string `json:"unit_id"`
	TimeStamp   int64  `json:"time_stamp"`
	EventSource string `json:"event_source"`
	EventType   string `json:"event_type"`
	Request     string `json:"request"`
	RemoteAddr  string `json:"remote_addr"`
}

type HTTPResponseConfig struct {
	CommonResponseComponent
	GroupID string `json:"groupID"`
}

type HTTPServerConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	ListenIP   string `json:"listen_ip" yaml:"listen_ip"`
	ListenPort string `json:"listen_port" yaml:"listen_port"`
	IPHeader   string `json:"ip_header" yaml:"ip_header" #:"在哪个 http header 中取 ip，为空代表从 REMOTE_ADDR 中取"`
}

type ListEventResp struct {
	Events []*Event `json:"events"`
	Total  int      `json:"total"`
}

type PayloadTemplate struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Suffix      string `json:"suffix"`
	CommonResponseComponent
}

type RMIServerConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	ListenIP   string `json:"listen_ip" yaml:"listen_ip"`
	ListenPort string `json:"listen_port" yaml:"listen_port"`
}

type ResolveConfig struct {
	Type   string `json:"type" yaml:"type" #:"A, AAAA, TXT 三种"`
	Record string `json:"record" yaml:"record"`
	Value  string `json:"value" yaml:"value"`
	TTL    uint32 `json:"ttl" yaml:"ttl"`
}

type Response struct {
	ResponseBase
	Data interface{} `json:"data"`
}

type ResponseBase struct {
	Code int `json:"code"`
}
