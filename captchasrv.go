package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:generate go run gentmpl.go form success

var (
	// Generate using e.g. “openssl rand -hex 32”.
	hmacSecretStr = flag.String("hmac_secret_key",
		"",
		"Shared secret key between RobustIRC and captchasrv for message HMACs")
	hmacSecret []byte

	recaptchaSiteKey = flag.String("recaptcha_site_key",
		"",
		"Site key, from the Adding reCAPTCHA to your site section")

	recaptchaSecretKey = flag.String("recaptcha_secret_key",
		"",
		"Site key, from the Adding reCAPTCHA to your site section")

	listenAddr = flag.String("listen",
		":8080",
		"host:port to listen on for HTTP requests")
)

func verifyCaptcha(response string) error {
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify",
		url.Values{
			// remoteip is deliberately not set to make it easier to deploy
			// captchasrv behind a proxy and/or docker.
			"secret":   {*recaptchaSecretKey},
			"response": {response}})
	if err != nil {
		return err
	}

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		return fmt.Errorf("Unexpected HTTP status code verifying captcha: got %d, want %d", got, want)
	}

	defer func() {
		ioutil.ReadAll(resp.Body)
		resp.Body.Close()
	}()

	var reply struct {
		Success bool `json:"success"`
		// TODO: challenge_ts
		Hostname   string   `json:"hostname"`
		ErrorCodes []string `json:"error-codes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return fmt.Errorf("Error decoding JSON: %v", err)
	}

	// TODO: should we verify hostname?

	if !reply.Success {
		return errors.New("captcha unsuccessful")
	}

	return nil
}

type request struct {
	// response holds the captcha response, from the g-recaptcha-response HTTP
	// form value.
	response string

	// purpose, challenge and mac hold the randomly generated per-RobustSession
	// challenge purpose, value and corresponding Message Authentication Code
	// (unverified), decoded from the challenge HTTP form value.
	purpose   []byte
	challenge []byte
	mac       []byte
}

// fromHTTP constructs a request from an HTTP request. Any error will be
// displayed verbatim to the client (attacker).
func fromHTTP(r *http.Request) (request, error) {
	var result request
	if got, want := r.Method, "POST"; got != want {
		return result, fmt.Errorf("Invalid HTTP method: got %q, want %q", got, want)
	}

	if result.response = r.FormValue("g-recaptcha-response"); result.response == "" {
		return result, fmt.Errorf("g-recaptcha-response parameter not set")
	}

	challenge := r.FormValue("challenge")
	if challenge == "" {
		return result, fmt.Errorf("challenge parameter not set")
	}

	parts := strings.Split(challenge, ".")
	if got, want := len(parts), 3; got != want {
		return result, fmt.Errorf("Unexpected number of challenge parts: got %d, want %d", got, want)
	}

	decoded := make([][]byte, 3)
	var err error
	for idx, part := range parts {
		decoded[idx], err = base64.StdEncoding.DecodeString(part)
		if err != nil {
			return result, err
		}
	}

	result.purpose = decoded[0]
	result.challenge = decoded[1]
	result.mac = decoded[2]

	return result, nil
}

func writeForm(w http.ResponseWriter, msg string) {
	if err := formTpl.Execute(w, struct {
		SiteKey string
		Msg     string
	}{
		SiteKey: *recaptchaSiteKey,
		Msg:     msg,
	}); err != nil {
		log.Printf("rendering form: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	flag.Parse()

	if *recaptchaSiteKey == "" {
		log.Fatalf("-recaptcha_site_key is required")
	}

	if *recaptchaSecretKey == "" {
		log.Fatalf("-recaptcha_secret_key is required")
	}

	var err error
	hmacSecret, err = hex.DecodeString(*hmacSecretStr)
	if err != nil {
		log.Fatalf("Could not decode -hmac_secret=%q as hex string: %v", hmacSecretStr, err)
	}

	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		req, err := fromHTTP(r)
		if err != nil {
			log.Printf("bad request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// First verify the captcha was solved correctly in order to prevent
		// attackers from driving up processing cost.
		if err := verifyCaptcha(req.response); err != nil {
			log.Printf("verifyCaptcha: %v", err)
			writeForm(w, "Captcha could not be verified")
			return
		}

		// Verify the challenge actually came from RobustIRC before issuing a
		// token, so that attackers cannot generate tokens in advance by
		// solving captchas.
		mac := hmac.New(sha256.New, hmacSecret)
		mac.Write(req.purpose)
		mac.Write(req.challenge)
		if !hmac.Equal(req.mac, mac.Sum(nil)) {
			writeForm(w, "Challenge could not be verified")
			return
		}

		// Craft the authenticated captcha confirmation message to RobustIRC.
		mac = hmac.New(sha256.New, hmacSecret)
		purpose := []byte("okay:" + string(req.purpose))
		mac.Write(purpose)
		mac.Write(req.challenge)
		token := strings.Join([]string{
			base64.StdEncoding.EncodeToString(purpose),
			base64.StdEncoding.EncodeToString(req.challenge),
			base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		}, ".")

		purposeparts := strings.Split(string(req.purpose), ":")

		if err := successTpl.Execute(w, struct {
			Purposeparts []string
			Token        string
		}{
			Purposeparts: purposeparts,
			Token:        token,
		}); err != nil {
			log.Printf("rendering form: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set cache time to one hour, so that frontends like CloudFlare can
		// serve this request for us.
		utc := time.Now().UTC()
		cacheSince := utc.Format(http.TimeFormat)
		cacheUntil := utc.Add(1 * time.Hour).Format(http.TimeFormat)
		w.Header().Set("Cache-Control", "max-age=3600, public")
		w.Header().Set("Last-Modified", cacheSince)
		w.Header().Set("Expires", cacheUntil)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		writeForm(w, "")
	})

	http.ListenAndServe(*listenAddr, nil)
}
