package warnlist

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	DomainFileFormatHostfile = "hostfile"
	DomainFileFormatTextList = "text"
	DomainSourceTypeFile     = "file"
	DomainSourceTypeURL      = "url"
	DomainSourceTypeJSON     = "json"
)

var loginStatus = false
var accessToken = ""

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

func domainsFromSource(source string, sourceType string, sourceFormat string) chan string {

	c := make(chan string)

	go func() {
		defer close(c)

		var sourceData io.Reader
		{
			if sourceType == DomainSourceTypeFile {
				log.Infof("Loading from file: %s", source)
				file, err := os.Open(source)
				if err != nil {
					log.Error(err)
				}
				defer file.Close()
				sourceData = file
			} else if sourceType == DomainSourceTypeURL {
				// TODO
				log.Infof("Loading from URL: %s", source)
				// Load the domain list from the URL
				if accessToken == "" {
					getAccessToken(source)
				}
				//log.Infof("access_token: %s", accessToken)
				req, _ := http.NewRequest("GET", source+"/abnormal_domain/all", nil)
				// 比如说设置个token
				req.Header.Set("Authorization", "Bearer "+accessToken)
				//log.Infof("%s", req.Header.Get("Authorization"))
				resp, err := (&http.Client{}).Do(req)
				if err != nil {
					log.Error(err)
				}
				if strings.Split(resp.Status, " ")[0] == "401" {
					getAccessToken(source)
				}
				defer resp.Body.Close()
				sourceData = resp.Body
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
				var dat map[string]string
				if err := json.Unmarshal([]byte(domain), &dat); err == nil {
					domain = dat["ip"] + " " + dat["domain"]
				} else {
					log.Error(err)
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
