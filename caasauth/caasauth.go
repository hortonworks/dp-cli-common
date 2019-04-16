package caasauth

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-openapi/runtime/client"
	"github.com/hortonworks/dp-cli-common/utils"
)

type tokenRequest struct {
	GrantType string `json:"grant_type"`
	Code      string `json:"code"`
	ClientId  string `json:"client_id"`
}

type refreshRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientId     string `json:"client_id"`
}

func newTokenRequest(code string) *tokenRequest {
	return &tokenRequest{
		GrantType: "authorization_code",
		Code:      code,
		ClientId:  "6eda2bf3-95ce-499b-8e27-1c19c93bae12",
	}
}

func newRefreshTokenRequest(refresh string) *refreshRequest {
	return &refreshRequest{
		GrantType:    "refresh_token",
		RefreshToken: refresh,
		ClientId:     "6eda2bf3-95ce-499b-8e27-1c19c93bae12",
	}
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func RefreshAccessToken(address, baseApiPath, refreshToken string) (*utils.Transport, *TokenResponse) {
	address, basePath := utils.CutAndTrimAddress(address)
	tokenReq := newRefreshTokenRequest(refreshToken)

	tokens, err := getCaasToken("https://"+address+basePath+"/oidc/token", tokenReq)
	if err != nil {
		utils.LogErrorAndExit(err)
	}
	cbTransport := &utils.Transport{client.New(address, basePath+baseApiPath, []string{"https"})}
	cbTransport.Runtime.DefaultAuthentication = client.BearerToken(tokens.AccessToken)
	cbTransport.Runtime.Transport = utils.LoggedTransportConfig
	return cbTransport, tokens
}

func NewRefreshToken(address string) string {
	_, tokens := NewCaasTransport(address, "")
	return tokens.RefreshToken
}

func NewCaasTransport(address, baseApiPath string) (*utils.Transport, *TokenResponse) {
	address, basePath := utils.CutAndTrimAddress(address)

	caasPath := fmt.Sprintf("https://%[1]s/oidc/authorize?scope=openid dps offline_access&response_type=code&client_id=6eda2bf3-95ce-499b-8e27-1c19c93bae12&redirect_uri=https://%[1]s/caas/cli&state=random-state&nonce=random-nonce", address+basePath)
	reader := bufio.NewReader(os.Stdin)
	printLink(utils.ConvertToURLAndEncode(caasPath))
	deviceCode, _ := reader.ReadString('\n')
	deviceCode = strings.TrimSuffix(deviceCode, "\n")
	tokenReq := newTokenRequest(deviceCode)

	cbTransport := &utils.Transport{client.New(address, basePath+baseApiPath, []string{"https"})}

	tokens, err := getCaasToken("https://"+address+basePath+"/oidc/token", tokenReq)
	if err != nil {
		utils.LogErrorAndExit(err)
	}
	cbTransport.Runtime.DefaultAuthentication = client.BearerToken(tokens.AccessToken)
	cbTransport.Runtime.Transport = utils.LoggedTransportConfig
	return cbTransport, tokens
}

func printLink(url *url.URL) {
	fmt.Println()
	fmt.Println(url)
	fmt.Println()
	fmt.Print("Enter security code: ")
}

func getCaasToken(identityUrl string, tokenReq interface{}) (*TokenResponse, error) {
	reqBody, _ := json.Marshal(tokenReq)
	req, err := http.NewRequest("POST", identityUrl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	c := &http.Client{
		Transport: utils.LoggedTransportConfig,
	}

	resp, err := c.Do(req)

	if resp == nil && err == nil {
		return nil, errors.New(fmt.Sprintf("Unknown error while connnecting to %s", identityUrl))
	}

	if resp == nil || resp.StatusCode >= 400 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New(fmt.Sprintf("Error while connnecting to %s, please check your username and password or use flags for each command. (%s)", identityUrl, resp.Status))
	}

	var tokenResp TokenResponse
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return nil, err
	}

	return &tokenResp, nil
}
