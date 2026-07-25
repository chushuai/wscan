/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
	logger "wscan/core/utils/log"
)

type Reverse struct {
	ctx                   context.Context
	cancel                func()
	config                *Config
	db                    *DB
	reverseHTTPServer     *HTTPServer
	reverseDNSServer      *DNSServer
	reverseRMIServer      *RMIServer
	reverseLdapServer     *LdapServer
	groupUnitCallbackMap  sync.Map
	internalGroupEventMap *sync.Map
	groupToDelete         remoteFetchEventRequest
}

func (r *Reverse) Config() *Config {
	return r.config
}

func (r *Reverse) healthCheck(ctx context.Context) error {
	url := fmt.Sprintf("http://%s/_/api/health_check", r.config.GetAddr()) // 替换为实际的地址和端口
	ticker := time.NewTicker(20 * time.Second)                             // 每隔 5 秒执行一次
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// 发起 HTTP GET 请求进行健康检查

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				logger.Errorf("health detection of anti-connection platform : %v", err)
				continue
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				logger.Errorf("health detection of anti-connection platform: %s %v", url, err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				logger.Errorf("health detection of anti-connection platform %s unexpected status code: %v", url, resp.StatusCode)
				continue
			}
			logger.Infof("health detection of anti-connection platform %s successful", url)
		}
	}
	return nil
}

func (r *Reverse) launchServer() error {
	r.reverseHTTPServer = NewHTTPServer(r.config, r.internalGroupEventMap, r.db)
	r.reverseRMIServer = NewRMIServer(r.config, r.internalGroupEventMap, r.db)
	r.reverseLdapServer = NewLdapServer(r.config, r.internalGroupEventMap, r.db)

	if r.config.DNSServerConfig.Enabled {
		if dnsServer, _ := NewDNSServer(r.config, r.internalGroupEventMap, r.db); dnsServer != nil {
			go dnsServer.Start()
		}
	}

	lis, err := net.Listen("tcp", r.config.HTTPServerConfig.GetAddr())
	if err != nil {
		logger.Fatal(err)
	}
	// Listener 会对HTTP/RMI/LDAP等协议进行复用同一个端口
	r.reverseHTTPServer.Server.Serve(NewListener(lis, r))
	return nil
}

func (r *Reverse) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

func (r *Reverse) prepareConfig() {
	httpServerCheckAndPrepare(r.config)
	// "domain must be set if IsDomainNameServer is true"

}

func NewReverse(config *Config) *Reverse {
	r := &Reverse{
		config:                config,
		internalGroupEventMap: &sync.Map{},
	}
	if !r.config.HTTPServerConfig.Enabled {
		if !r.config.ClientConfig.RemoteServer {
			return nil
		}
	}
	if r.config.ClientConfig.RemoteServer {
		if config.Token == "" {
			logger.Fatal("please fill in the token of reverse")
		}
	}

	r.prepareConfig()

	go r.gcExpiredGroup()
	go r.gcExpiredEventMap()
	go r.FetchEvent()

	if r.config.ClientConfig.RemoteServer {
		go r.healthCheck(context.Background())
	} else {
		if config.DBFilePath != "" {
			db := &DB{}
			err := db.Open(config.DBFilePath)
			if err != nil {
				logger.Fatal(err)
			}
			r.db = db
		} else {
			logger.Fatal("if you want to run standalone reverse server, you must set db_file_path in config file, or data will lost if process restarts")
		}
		go func() {
			// 本地
			r.launchServer()
			r.Close()
		}()
	}
	// Wait briefly for the reverse server to become ready.
	// TODO: replace with readiness channel signaled by launchServer.
	time.Sleep(2 * time.Second)
	return r
}
