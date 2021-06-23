package warnlist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	DomainStorageTypeMemory  = "memory"
	DomainStorageTypeFileDB  = "filedb"
	DomainFileFormatHostfile = "hostfile"
	DomainFileFormatTextList = "text"
	DomainSourceTypeFile     = "file"
	DomainSourceTypeURL      = "url"
	DomainSourceTypeJSON     = "json"
)

var loginStatus = false
var accessToken = ""

type Custom struct {
	UserId      int      `json:"user_id"`
	IPRange     []string `json:"ip_range"`
	Blacklist   []string `json:"black_list"`
	Whitelist   []string `json:"white_list"`
	BlockTarget string   `json:"block_target"`
}

func login(source string) (*http.Response, error) {
	resp, err := http.Post(source+"/account/login", "application/x-www-form-urlencoded", strings.NewReader("username=fuxi&password=fuxiDnS"))
	return resp, err
}

func getAccessToken(source string) {
	resp, err := login(source)
	if err != nil {
		log.Error(err)
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var dat map[string]string
		if err := json.Unmarshal([]byte(strings.TrimSpace(scanner.Text())), &dat); err == nil {
			accessToken = dat["access_token"]
		} else {
			log.Error(err)
		}
		break
	}
}

func requestAPI(url string) *http.Response {
	//log.Infof("access_token: %s", accessToken)
	req, _ := http.NewRequest("GET", url, nil)
	// 比如说设置个token
	req.Header.Set("Authorization", "Bearer "+accessToken)
	//log.Infof("%s", req.Header.Get("Authorization"))
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		log.Error(err)
	}
	return resp
}

func domainsFromSource(source string, sourceType string, sourceFormat string) chan string {

	c := make(chan string)

	go func() {
		defer close(c)

		var sourceData io.Reader
		{
			if sourceType == DomainSourceTypeFile {
				log.Debug("Loading from file: %s", source)
				file, err := os.Open(source)
				if err != nil {
					log.Error(err)
				}
				defer file.Close()
				sourceData = file
			} else if sourceType == DomainSourceTypeURL {
				// TODO
				log.Debug("Loading from URL: %s", source)
				// Load the domain list from the URL
				if accessToken == "" {
					getAccessToken(source)
				}
				resp := requestAPI(source + "/abnormal_domain/all")
				if strings.Split(resp.Status, " ")[0] == "401" {
					getAccessToken(source)
					resp = requestAPI(source + "/abnormal_domain/all")
				}
				defer resp.Body.Close()
				sourceData = resp.Body
				buf := new(bytes.Buffer)
				buf.ReadFrom(resp.Body)
				all_json := buf.String()

				resp = requestAPI(source + "/abnormal_domain/users")
				buf = new(bytes.Buffer)
				buf.ReadFrom(resp.Body)
				users_json := buf.String()

				sourceData = ioutil.NopCloser(strings.NewReader(all_json + users_json))
			}
		}
		scanner := bufio.NewScanner(sourceData)
		buf := make([]byte, 0, bufio.MaxScanTokenSize*10) //根据自己的需要调整这个倍数
		scanner.Buffer(buf, cap(buf))

		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			//log.Infof(domain)
			if strings.HasPrefix(domain, "#") {
				// Skip comment lines
				continue
			}

			if domain == "" {
				// Skip empty lines
				continue
			}

			if sourceFormat == DomainSourceTypeJSON {
				//domain = strings.Fields(domain)[1] // Assumes hostfile format:   127.0.0.1  some.host
				//log.Infof(domain)
				var dat map[string]string
				if err := json.Unmarshal([]byte(domain), &dat); err == nil {
					domain = "all " + dat["ip"] + " " + dat["domain"]
					//domain = dat["ip"] + " " + dat["domain"] + " " + redirectIP
				} else {
					var custom Custom
					if err := json.Unmarshal([]byte(domain), &custom); err == nil {
						//println(custom)
						domain = "users " + strconv.Itoa(custom.UserId) + " " + strings.Join(custom.IPRange, `,`) + " " + strings.Join(custom.Blacklist, `,`) + " " + strings.Join(custom.Whitelist, `,`) + " " + custom.BlockTarget
					} else {
						log.Error(err)
					}
				}
			}

			if sourceFormat == DomainFileFormatHostfile {
				//domain = strings.Fields(domain)[1] // Assumes hostfile format:   127.0.0.1  some.host
				domain = strings.Fields(domain)[0] + " " + strings.Fields(domain)[1] // Assumes hostfile format:   127.0.0.1  some.host
			}

			// Assume all domains are global origin, with trailing dot (e.g. example.com.)
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}

			c <- domain
		}
		if err := scanner.Err(); err != nil {
			log.Error(err)
		}
	}()

	return c

}
