/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"encoding/json"
	"golang.org/x/net/context"
	"sync"
)

type Reverse struct {
	ctx                   context.Context
	cancel                func()
	config                *Config
	db                    *DB
	reverseHTTPServer     *HTTPServer
	reverseDNSServer      *DNSServer
	reverseRMIServer      *RMIServer
	groupUnitCallbackMap  sync.Map
	internalGroupEventMap *sync.Map
	groupToDelete         remoteFetchEventRequest
}

func NewReverse(config *Config) *Reverse {
	r := &Reverse{config: config,
		reverseHTTPServer: NewHTTPServer(config),
		db:                &DB{},
	}
	if ds, err := NewDNSServer(config, r.db); err == nil {
		r.reverseDNSServer = ds
	}
	return r
}

func (r *Reverse) Start() {
	wg := sync.WaitGroup{}
	if r.config.HTTPServerConfig.Enabled == true {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.reverseHTTPServer.Start()
		}()

	}
	if r.config.DNSServerConfig.Enabled == true {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.reverseDNSServer.Start()
		}()
	}
	wg.Wait()
}

func (r *Reverse) Close() error {
	return nil
}

func (r *Reverse) Config() *Config {
	return r.config
}

var DnsData = make(map[string][]DnsInfo)

var DnsDataRwLock sync.RWMutex

type DnsInfo struct {
	Type      string
	Subdomain string
	Ipaddress string
	Time      int64
}

func (d *DnsInfo) Set(userDir string, data DnsInfo) {
	DnsDataRwLock.Lock()
	defer DnsDataRwLock.Unlock()
	if DnsData[userDir] == nil {
		DnsData[userDir] = []DnsInfo{data}
	} else {
		DnsData[userDir] = append(DnsData[userDir], data)
	}
}

func (d *DnsInfo) Get(userDir string) string {
	DnsDataRwLock.RLock()
	defer DnsDataRwLock.RUnlock()
	res := ""
	if DnsData[userDir] != nil {
		v, _ := json.Marshal(DnsData[userDir])
		res = string(v)
	}
	if res == "" {
		res = "null"
	}
	return res
}

func (d *DnsInfo) Clear(userDir string) {
	DnsData[userDir] = []DnsInfo{}
	DnsData["other"] = []DnsInfo{}
}

var D DnsInfo

/*

var D DnsInfo

*/
/*

func (r *Reverse) FetchEvent() {
	// Use context to control the overall execution time
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()

	// Fetch events locally
	r.localFetchEvent()

	// Fetch events remotely
	err := r.remoteFetchEvent()
	if err != nil {
		// Handle the error (log, return, or take appropriate action)
		fmt.Printf("Error fetching remote events: %v\n", err)
	}
}
func (*Reverse) NewUnitGroup() *UnitGroup {
	return nil
}
func (*Reverse) Register(unitInterface interface{}) *Unit {
	// Check if the provided interface is of type *Unit
	unit, ok := unitInterface.(*Unit)
	if !ok {
		// Handle the error (log, return, or take appropriate action)
		fmt.Println("Invalid unit interface provided.")
		return nil
	}

	// Optionally, perform additional validations or checks on the unit
	// ...

	// Register the unit
	// You might want to use a unique identifier for each unit
	unitID := generateUniqueID() // Replace with your actual method for generating IDs
	r.groupUnitCallbackMap.Store(unitID, unit)

	// Optionally, perform additional actions after registration
	// ...

	return unit
}
func (r *Reverse) RegisterWithGroup(unitInterface interface{}, group *UnitGroup) *Unit {
	// Check if the provided interface is of type *Unit
	unit, ok := unitInterface.(*Unit)
	if !ok {
		// Handle the error (log, return, or take appropriate action)
		fmt.Println("Invalid unit interface provided.")
		return nil
	}

	// Check if the provided group is nil
	if group == nil {
		// Handle the error (log, return, or take appropriate action)
		fmt.Println("Group cannot be nil.")
		return nil
	}

	// Add the unit to the specified group
	group.AddUnit(unit)

	// Optionally, you can perform additional actions or validations here

	return unit
	return nil
}
func (r *Reverse) gcExpiredEventMap() {
	// Get the current time
	currentTime := time.Now()

	// Iterate over the items in the internal group event map
	r.internalGroupEventMap.Range(func(key, value interface{}) bool {
		// Assuming that the value is a slice of events ([]*Event)
		events, ok := value.([]*Event)
		if !ok {
			// Handle the unexpected value type (log, return, or take appropriate action)
			fmt.Println("Unexpected value type in internal group event map.")
			return true
		}

		// Filter out expired events
		filteredEvents := make([]*Event, 0, len(events))
		for _, event := range events {
			// Assuming that Event has an 'ExpirationTime' field
			if event.ExpirationTime.After(currentTime) {
				filteredEvents = append(filteredEvents, event)
			}
		}

		// Update the value in the map with the filtered events
		r.internalGroupEventMap.Store(key, filteredEvents)

		return true
	})
}
func (r *Reverse) gcExpiredGroup() {
	// Get the current time
	//currentTime := time.Now()
	//
	//// Iterate over the groupUnitCallbackMap
	//r.groupUnitCallbackMap.Range(func(key, value interface{}) bool {
	//	// Assuming that the value is a UnitGroup
	//	group, ok := value.(*UnitGroup)
	//	if !ok {
	//		// Handle the unexpected value type (log, return, or take appropriate action)
	//		fmt.Println("Unexpected value type in groupUnitCallbackMap.")
	//		return true
	//	}
	//
	//	// Assuming that UnitGroup has an 'ExpirationTime' field
	//	if group.ExpirationTime.Before(currentTime) {
	//		// The group has expired, remove it from the map
	//		r.groupUnitCallbackMap.Delete(key)
	//		fmt.Printf("Expired group deleted: %v\n", key)
	//	}
	//
	//	return true
	//})
}
func (*Reverse) healthCheck(context.Context) error {
	return nil
}

func (r *Reverse) launchServer() error {
	// Launch HTTP server
	httpErrCh := make(chan error)
	go func() {
		err := r.reverseHTTPServer.Server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			httpErrCh <- err
		}
		close(httpErrCh)
	}()

	// Launch DNS server
	dnsErrCh := make(chan error)
	go func() {
		err := r.reverseDNSServer.ListenAndServe()
		if err != nil {
			dnsErrCh <- err
		}
		close(dnsErrCh)
	}()

	// Launch RMI server
	rmiErrCh := make(chan error)
	go func() {
		err := r.reverseRMIServer.Serve()
		if err != nil {
			rmiErrCh <- err
		}
		close(rmiErrCh)
	}()

	// Wait for any server to return an error or for the context to be canceled
	select {
	case err := <-httpErrCh:
		return fmt.Errorf("HTTP server error: %v", err)
	case err := <-dnsErrCh:
		return fmt.Errorf("DNS server error: %v", err)
	case err := <-rmiErrCh:
		return fmt.Errorf("RMI server error: %v", err)
	case <-r.ctx.Done():
		// Context canceled, shut down the servers gracefully
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := r.reverseHTTPServer.Server.Shutdown(shutdownCtx); err != nil {
			fmt.Println("Error shutting down HTTP server:", err)
		}

		if err := r.reverseDNSServer.Shutdown(shutdownCtx); err != nil {
			fmt.Println("Error shutting down DNS server:", err)
		}

		r.reverseRMIServer.Close()

		return nil
	}
}

func (r *Reverse) localCallUnitCallback() {
	// Iterate over the units in the groupUnitCallbackMap
	r.groupUnitCallbackMap.Range(func(key, value interface{}) bool {
		// Assuming that the value is a *Unit
		unit, ok := value.(*Unit)
		if !ok {
			// Handle the unexpected value type (log, return, or take appropriate action)
			fmt.Println("Unexpected value type in groupUnitCallbackMap.")
			return true
		}

		// Call the callback function of the unit
		unit.Callback()

		// Optionally, perform additional actions after calling the callback
		// ...

		return true
	})
}
func (r *Reverse) localFetchEvent() {
	// Assuming DB is a BoltDB database
	// You need to replace it with your actual local storage implementation
	r.db.Lock()
	defer r.db.Unlock()

	err := r.db.View(func(tx *bbolt.Tx) error {
		// Access the bucket or storage where events are stored
		bucket := tx.Bucket([]byte("events"))
		if bucket == nil {
			// Handle the case where the bucket doesn't exist
			return nil
		}

		// Iterate over events and process them
		err := bucket.ForEach(func(key, value []byte) error {
			// Assuming you have some deserialization logic here
			var event Event
			if err := json.Unmarshal(value, &event); err != nil {
				// Handle the error (log, return, or take appropriate action)
				fmt.Printf("Error decoding event: %v\n", err)
				return nil // Continue iterating
			}

			// Process the event as needed
			fmt.Printf("Local Event: %+v\n", event)

			return nil // Continue iterating
		})

		return err
	})

	if err != nil {
		// Handle the error (log, return, or take appropriate action)
		fmt.Printf("Error fetching local events: %v\n", err)
	}
}
func (*Reverse) prepareConfig() {

}

// Assuming there's a remote server URL to fetch events
const remoteServerURL = "https://example.com/fetch-events"

func (r *Reverse) remoteFetchEvent() error {
	// Create a new context with timeout for the HTTP request
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteServerURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers, authentication, or any other required settings
	req.Header.Set("Authorization", "Bearer "+r.config.Token)

	// Send the HTTP request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch events: %v", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Decode the response body
	var eventResponse fetchEventResponse
	if err := json.NewDecoder(resp.Body).Decode(&eventResponse); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	// Process the fetched events (use eventResponse.Event)
	// TODO: Implement your logic for handling the events

	return nil
}
*/
