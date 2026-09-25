package iamproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIMDSv2CredentialFlow(t *testing.T) {
	s, _ := fixtureService(t)
	s.Config.Principals[0].AWSSessionToken = "fixture-session"
	now := s.Now()
	s.Now = func() time.Time { return now }
	h := s.HTTPHandler()
	server := httptest.NewServer(h)
	defer server.Close()
	credentialsURL := server.URL + "/latest/meta-data/iam/security-credentials/alice"
	response, err := http.Get(credentialsURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("IMDSv1 request returned %d", response.StatusCode)
	}
	request, _ := http.NewRequest("PUT", server.URL+"/latest/api/token", nil)
	request.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "0")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("invalid TTL returned %d", response.StatusCode)
	}
	request, _ = http.NewRequest("PUT", server.URL+"/latest/api/token", nil)
	request.Header.Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "2")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(body))
	if response.StatusCode != 200 || token == "" {
		t.Fatal("IMDSv2 token request failed")
	}
	request, _ = http.NewRequest("GET", credentialsURL, nil)
	request.Header.Set("X-Aws-Ec2-Metadata-Token", token)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var credentials struct {
		AccessKeyID string `json:"AccessKeyId"`
		Token       string `json:"Token"`
	}
	err = json.NewDecoder(response.Body).Decode(&credentials)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || credentials.AccessKeyID != "AKIATEST" || credentials.Token != "fixture-session" {
		t.Fatal("wrong role credentials")
	}
	now = now.Add(3 * time.Second)
	request, _ = http.NewRequest("GET", credentialsURL, nil)
	request.Header.Set("X-Aws-Ec2-Metadata-Token", token)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("expired IMDSv2 token returned %d", response.StatusCode)
	}
}

func TestECSCredentialAndTaskMetadata(t *testing.T) {
	s, _ := fixtureService(t)
	s.Config.Principals[0].AWSSessionToken = "ecs-session"
	s.Config.Principals[0].ECSAuthorizationToken = "ecs-auth"
	server := httptest.NewServer(s.HTTPHandler())
	defer server.Close()
	credentialURL := server.URL + "/v2/credentials/alice"
	response, err := http.Get(credentialURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized credential request returned %d", response.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodGet, credentialURL, nil)
	request.Header.Set("Authorization", "ecs-auth")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var credential struct {
		AccessKeyID string `json:"AccessKeyId"`
		Token       string `json:"Token"`
		RoleARN     string `json:"RoleArn"`
	}
	if err := json.NewDecoder(response.Body).Decode(&credential); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || credential.AccessKeyID != "AKIATEST" || credential.Token != "ecs-session" || credential.RoleARN == "" {
		t.Fatalf("invalid ECS credential response: %+v", credential)
	}
	response, err = http.Get(server.URL + "/ecs/v4/alice/task")
	if err != nil {
		t.Fatal(err)
	}
	var task struct {
		TaskARN    string `json:"TaskARN"`
		Containers []struct {
			Name string `json:"Name"`
		} `json:"Containers"`
	}
	if err := json.NewDecoder(response.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || task.TaskARN == "" || len(task.Containers) != 1 || task.Containers[0].Name != "alice" {
		t.Fatalf("invalid ECS task metadata: %+v", task)
	}
	response, err = http.Get(server.URL + "/ecs/v4/alice/task/stats")
	if err != nil {
		t.Fatal(err)
	}
	var stats map[string]json.RawMessage
	if err := json.NewDecoder(response.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || len(stats["iam-proxy-alice"]) == 0 {
		t.Fatal("invalid ECS task stats")
	}
}
