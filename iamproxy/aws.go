package iamproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func awsHMAC(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func awsEncode(s string) string {
	const hexchars = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexchars[c>>4])
			b.WriteByte(hexchars[c&15])
		}
	}
	return b.String()
}

func awsQuery(v url.Values) string {
	var pairs []string
	for k, values := range v {
		for _, value := range values {
			pairs = append(pairs, awsEncode(k)+"="+awsEncode(value))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func (s *service) validateAWS(l Listener, username, token string) (*Principal, error) {
	if strings.Contains(token, "://") {
		return nil, errors.New("scheme not allowed")
	}
	u, err := url.Parse("https://" + token)
	// aws-sdk-go-v2 rds/auth.BuildAuthToken signs "host:port?query" with an
	// empty path; SigV4 canonicalizes that to "/", as used below.
	if err != nil || u.User != nil || u.Fragment != "" || u.RawPath != "" || u.Path != "/" && u.Path != "" {
		return nil, errors.New("invalid token URL")
	}
	_, port, err := net.SplitHostPort(l.Listen)
	if err != nil || u.Host != net.JoinHostPort(l.Hostname, port) {
		return nil, errors.New("wrong endpoint")
	}
	v, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	for _, values := range v {
		if len(values) != 1 {
			return nil, errors.New("duplicate query key")
		}
	}
	if v.Get("Action") != "connect" || v.Get("DBUser") != username || v.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || v.Get("X-Amz-SignedHeaders") != "host" {
		return nil, errors.New("invalid query")
	}
	sig := v.Get("X-Amz-Signature")
	if len(sig) != 64 {
		return nil, errors.New("missing signature")
	}
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return nil, err
	}
	exp, err := strconv.Atoi(v.Get("X-Amz-Expires"))
	if err != nil || exp < 1 || exp > 900 {
		return nil, errors.New("invalid expiry")
	}
	date := v.Get("X-Amz-Date")
	issued, err := time.Parse("20060102T150405Z", date)
	if err != nil || s.Now().Before(issued.Add(-5*time.Minute)) || !s.Now().Before(issued.Add(time.Duration(exp)*time.Second)) {
		return nil, errors.New("expired token")
	}
	cred := strings.Split(v.Get("X-Amz-Credential"), "/")
	if len(cred) != 5 || cred[1] != date[:8] || cred[2] != l.Region || cred[3] != "rds-db" || cred[4] != "aws4_request" {
		return nil, errors.New("wrong credential scope")
	}
	var p *Principal
	for i := range s.Config.Principals {
		if s.Config.Principals[i].AWSAccessKey == cred[0] {
			p = &s.Config.Principals[i]
			break
		}
	}
	if p == nil || p.AWSSecretKey == "" || v.Get("X-Amz-Security-Token") != p.AWSSessionToken {
		return nil, errors.New("unknown credential")
	}
	delete(v, "X-Amz-Signature")
	canonical := "GET\n/\n" + awsQuery(v) + "\nhost:" + u.Host + "\n\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hash := sha256.Sum256([]byte(canonical))
	scope := strings.Join(cred[1:], "/")
	stringToSign := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	k := awsHMAC([]byte("AWS4"+p.AWSSecretKey), cred[1])
	k = awsHMAC(k, cred[2])
	k = awsHMAC(k, "rds-db")
	k = awsHMAC(k, "aws4_request")
	expected := awsHMAC(k, stringToSign)
	if subtle.ConstantTimeCompare(expected, sigBytes) != 1 {
		return nil, fmt.Errorf("invalid signature")
	}
	return p, nil
}
