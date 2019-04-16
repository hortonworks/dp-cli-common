package apikeyauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/hortonworks/dp-cli-common/utils"
	ed "golang.org/x/crypto/ed25519"
)

const (
	AltusAuthHeader = "x-altus-auth"
	AltusDateHeader = "x-altus-date"
)

var signPattern string = "%s\napplication/json\n%s\n%s\ned25519v1"

type metastr struct {
	AccessKey  string `json:"access_key_id"`
	AuthMethod string `json:"auth_method"`
}

func newMetastr(accessKeyId string) *metastr {
	return &metastr{accessKeyId, "ed25519v1"}
}

func GetAPIKeyAuthTransport(address, baseApiPath, accessKeyId, privateKey string) *utils.Transport {
	address, basePath := utils.CutAndTrimAddress(address)

	cbTransport := &utils.Transport{client.New(address, basePath+baseApiPath, []string{"https"})}
	cbTransport.Runtime.DefaultAuthentication = AltusAPIKeyAuth(accessKeyId, privateKey)
	cbTransport.Runtime.Transport = utils.LoggedTransportConfig
	return cbTransport
}

func AltusAPIKeyAuth(accessKeyId, privateKey string) runtime.ClientAuthInfoWriter {
	return runtime.ClientAuthInfoWriterFunc(func(r runtime.ClientRequest, _ strfmt.Registry) error {
		date := formatdate()
		err := r.SetHeaderParam(AltusAuthHeader, authHeader(accessKeyId, privateKey, r.GetMethod(), r.GetPath(), date))
		if err != nil {
			return err
		}
		return r.SetHeaderParam(AltusDateHeader, date)
	})
}

func authHeader(accessKeyId, privateKey, method, path, date string) string {
	return fmt.Sprintf("%s.%s", urlsafeMeta(accessKeyId), urlsafeSignature(privateKey, method, path, date))
}

func urlsafeSignature(seedBase64, method, path, date string) string {
	seed, err := base64.StdEncoding.DecodeString(seedBase64)
	if err != nil {
		utils.LogErrorAndExit(err)
	}
	k := ed.NewKeyFromSeed(seed)
	message := fmt.Sprintf(signPattern, method, date, path)
	log.Debugf("Message to sign: \n%s", message)
	signature := ed.Sign(k, []byte(message))
	return urlsafeBase64Encode(signature)
}

func urlsafeMeta(accessKeyId string) string {
	b, err := json.Marshal(newMetastr(accessKeyId))
	if err != nil {
		utils.LogErrorAndExit(err)
	}
	return string(urlsafeBase64Encode(b))
}

func urlsafeBase64Encode(data []byte) string {
	return fmt.Sprint(base64.URLEncoding.EncodeToString(data))
}

func formatdate() string {
	layout := "Mon, 02 Jan 2006 15:04:05 GMT"
	return fmt.Sprint(time.Now().UTC().Format(layout))
}
