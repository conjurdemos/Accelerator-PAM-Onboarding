package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

var (
	version         = "dev"
	DEBUG           = false
	TLS_SKIP_VERIFY = false
	CLI             CLIparams
	CONF            = koanf.New(".")
	CONFPARSER      = toml.Parser()
	DebugLogger     *log.Logger
	PASCONF         ToolshedPASVaultConfig
)

func main() {
	ParseParams() // command line params
	DebugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	if !DEBUG {
		DebugLogger.SetOutput(io.Discard) // turn off debug output
	}
	LoadConfigs() // load config files into CONF
	CONF.Unmarshal("pasvault", &PASCONF)
	PASCONF.User = *CLI.pasuser
	PASCONF.Pass = *CLI.paspass

	// Figure out which AWS creds to use
	awscreds, err := GetAWSProviderCredentials()
	if err != nil {
		log.Fatalf("ERROR: could not acquire AWS Provider credentials: %s\n", err.Error())
	}

	// Provision the EC2 instance
	result, err := CreateInstanceCmd(awscreds)
	if err != nil {
		log.Fatalf("ERROR: could not create instance: %s\n", err.Error())
	}

	// Add the instance info to the PAS Vault safe
	AddVaultAccount(result)
}

type IDTenantResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type ToolshedPASVaultConfig struct {
	IDTenantURL string `koanf:"idtenanturl"`
	PCloudURL   string `koanf:"pcloudurl"`
	SafeName    string `koanf:"safename"`
	User        string `koanf:"user"`
	Pass        string `koanf:"pass"`
}

type ToolshedConjurConfig struct {
	APIURL                  string `koanf:"apiurl"`
	Account                 string `koanf:"account"`
	Identity                string `koanf:"identity"`
	Authenticator           string `koanf:"authenticator"`
	AWSRegion               string `koanf:"awsregion"`
	AWSAccessKey            string `koanf:"awsaccesskey"`
	AWSAccessSecret         string `koanf:"awsaccesssecret"`
	AWSProviderAccessKey    string `koanf:"awsprovideraccesskeypath"`
	AWSProviderAccessSecret string `koanf:"awsprovideraccesssecretpath"`
	AWSRoleToAssumeArn      string `koanf:"awsassumerolearn"`
}

type AWSProviderCredentials struct {
	Region       string `koanf:"region"`       // MUST ALWAYS BE SET
	AccessKey    string `koanf:"accesskey"`    // do NOT set when using Conjur
	AccessSecret string `koanf:"accesssecret"` // do NOT set when using Conjur
}

// CLIparams  Add CLI param fields here, and add processing of params to func ParseParams()
type CLIparams struct {
	debug         *bool // print extra info to console
	ver           *bool // Print Version and exit
	tlsskipverify *bool // skip TLS verify when calling Conjur (when conjur is configured with self-signed cert)

	// User Provided Input
	tagname  *string // AWS Tag name
	tagvalue *string // AWS Tag value
	keyname  *string // AWS Keypair name to create
	ami      *string // AMI ID, ex: ami-1234567890

	// Provision Engine Configurations
	pasfile *string // PAS Vault toml config file path
	pasuser *string // PAS User
	paspass *string // PAS Pass

	awsfile    *string // AWS Provider toml config file path
	conjurfile *string // Conjur toml config file path
}

// ParseParams puts cmdline params into CLI var
func ParseParams() {
	CLI.debug = flag.Bool("d", false, "Enable debug settings")
	CLI.ver = flag.Bool("version", false, "Print version")
	CLI.tlsskipverify = flag.Bool("tls-skip-verify", false, "Skip TLS Verify when calling conjur and pas (for self-signed cert)")

	CLI.tagname = flag.String("n", "", "The name of the tag to attach to the instance")
	CLI.tagvalue = flag.String("v", "", "The value of the tag to attach to the instance")
	CLI.keyname = flag.String("k", "", "The name of the keypair to use")
	CLI.ami = flag.String("a", "", "The AMI to use")

	CLI.pasfile = flag.String("pasconfig", "pasconfig.toml", "PAS Vault TOML config file, default is 'pasconfig.toml'")
	CLI.pasuser = flag.String("pasuser", "pasconfig.toml", "PAS Vault TOML config file, default is 'pasconfig.toml'")
	CLI.paspass = flag.String("paspass", "pasconfig.toml", "PAS Vault TOML config file, default is 'pasconfig.toml'")

	CLI.awsfile = flag.String("awsconfig", "awsconfig.toml", "AWS Provider creds TOML config file, default is 'awsconfig.toml'")
	CLI.conjurfile = flag.String("conjurconfig", "conjurconfig.toml", "Conjur TOML config file, default is 'conjurconfig.toml'")

	flag.Parse()

	DEBUG = *CLI.debug
	if *CLI.ver {
		log.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	TLS_SKIP_VERIFY = *CLI.tlsskipverify

	msg := ""
	if *CLI.tagname == "" || *CLI.tagvalue == "" {
		msg += "You must supply a name and value for the tag (-n NAME -v VALUE)\n"
	}
	if *CLI.keyname == "" {
		msg += "You must supply a keypair name (-k KEYPAIR-NAME) if not exists, one will be created\n"
	}
	if *CLI.ami == "" {
		msg += "You must supply an AMI name (-a AMI-NAME), ex: -a \"ami-05cc83e573412838f\"\n"
	}
	if *CLI.pasuser == "" || *CLI.paspass == "" {
		msg += "You must set both -pasuser and -paspass"
	}
	if len(msg) > 0 {
		log.Fatalf("%s\n", msg)
	}
}

// LoadConfigs load config files
func LoadConfigs() {

	// REQUIRED - Fail if no PAS Config
	if err := CONF.Load(file.Provider(*CLI.pasfile), CONFPARSER); err != nil {
		log.Fatalf("error loading PAS config: %v", err)
	}

	// REQUIRED - must set the AWS Region where resources will be created
	if _, err := os.Stat(*CLI.awsfile); err != nil {
		log.Fatalf("error with AWS config toml file: %v", err)
	}
	if err := CONF.Load(file.Provider(*CLI.awsfile), CONFPARSER); err != nil {
		log.Fatalf("error loading AWS config: %v", err)
	}

	// OPTIONAL - Conjur config
	if _, err := os.Stat(*CLI.conjurfile); err == nil {
		if err := CONF.Load(file.Provider(*CLI.conjurfile), CONFPARSER); err != nil {
			log.Fatalf("error loading Conjur config: %v", err)
		}
	}
}

// ----------------------------------------
// PASClient
// ----------------------------------------

// PASClient contains the data necessary for requests to pass successfully
type PASClient struct {
	BaseURL      string
	AuthType     string
	SessionToken string
	PASConfig    ToolshedPASVaultConfig
}

// PASAddAccountInput request used to create an account
type PASAddAccountInput struct {
	Name       string `json:"name,omitempty"`
	Address    string `json:"address"`
	UserName   string `json:"userName"`
	PlatformID string `json:"platformId"`
	SafeName   string `json:"safeName"`
	SecretType string `json:"secretType"`
	Secret     string `json:"secret"`
}

// PASAddAccountOutput response from getting specific account details
type PASAddAccountOutput struct {
	CategoryModificationTime  int                 `json:"categoryModificationTime"`
	ID                        string              `json:"id"`
	Name                      string              `json:"name"`
	Address                   string              `json:"address"`
	UserName                  string              `json:"userName"`
	PlatformID                string              `json:"platformId"`
	SafeName                  string              `json:"safeName"`
	SecretType                string              `json:"secretType"`
	PlatformAccountProperties map[string]string   `json:"platformAccountProperties"`
	SecretManagement          PASSecretManagement `json:"secretManagement"`
	CreatedTime               int                 `json:"createdTime"`
}

// PASSecretManagement used in getting and setting accounts
type PASSecretManagement struct {
	AutomaticManagementEnabled bool   `json:"automaticManagementEnabled"`
	Status                     string `json:"status"`
	ManualManagementReason     string `json:"manualManagementReason,omitempty"`
	LastModifiedTime           int    `json:"lastModifiedTime,omitempty"`
}

// GetProviderCredentials credentials to enable provider to provision resources
func GetAWSProviderCredentials() (*AWSProviderCredentials, error) {

	// assume all the awsprovider vars are in CONF
	awscreds := &AWSProviderCredentials{}
	CONF.Unmarshal("awsprovider", awscreds)

	if awscreds.Region != "" && awscreds.AccessKey != "" && awscreds.AccessSecret != "" {
		return awscreds, nil
	}

	// assume all the conjur vars are set in the Conjur configfile
	if *CLI.conjurfile != "" {
		creds, err := FetchAWSProviderCredsFromConjur()
		if err != nil {
			log.Fatalf("failed to fetch creds from Conjur: %s", err.Error())
		}
		awscreds.AccessKey = creds.AccessKey
		awscreds.AccessSecret = creds.AccessSecret
	}

	if awscreds.Region == "" {
		log.Fatalf("missing AWS credentials Region")
	}
	if awscreds.AccessKey == "" {
		log.Fatalf("missing AWS credentials AccessKey")
	}
	if awscreds.AccessSecret == "" {
		log.Fatalf("missing AWS credentials AccessSecret")
	}
	return awscreds, nil
}

// ----------------------------------------
// Handle provisioning of resources

// CreateInstanceCmd provision New keypair and New AWS instance
func CreateInstanceCmd(awscreds *AWSProviderCredentials) (*PASAddAccountInput, error) {

	pasdata := &PASAddAccountInput{
		Name:       "",
		Address:    "",
		UserName:   "",
		PlatformID: "",
		SafeName:   "",
		SecretType: "",
		Secret:     "",
	}

	log.Printf("Provisioning:\n\tAMI: %s\n\tTAG: %s=%s\n\tKPN: %s\n", *CLI.ami, *CLI.tagname, *CLI.tagvalue, *CLI.keyname)

	var clientLogModeFlags aws.ClientLogMode
	if DEBUG {
		clientLogModeFlags = aws.LogRetries | aws.LogRequest | aws.LogRequestWithBody | aws.LogResponse | aws.LogResponseWithBody | aws.LogDeprecatedUsage | aws.LogRequestEventMessage | aws.LogResponseEventMessage
	}

	var cfg aws.Config
	var err error

	cfg, err = config.LoadDefaultConfig(context.TODO(),
		config.WithClientLogMode(clientLogModeFlags),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awscreds.AccessKey, awscreds.AccessSecret, "")))
	cfg.Region = awscreds.Region

	if err != nil {
		panic("configuration error, " + err.Error())
	}

	client := ec2.NewFromConfig(cfg)

	// Create a keypair to use for the new instance
	keypairID, privKey := CreateKeyPair(*client, *CLI.keyname)
	if privKey == "" {
		return pasdata, fmt.Errorf("failed to create key pair")
	}

	// Create separate values if required.
	minMaxCount := int32(1)

	input := &ec2.RunInstancesInput{
		ImageId:      aws.String(*CLI.ami),
		InstanceType: types.InstanceTypeT3Medium,
		MinCount:     &minMaxCount,
		MaxCount:     &minMaxCount,
		KeyName:      CLI.keyname,
	}

	result, err := client.RunInstances(context.TODO(), input)
	if err != nil {
		return pasdata, fmt.Errorf("got an error creating an instance: %s", err)
	}

	instanceID := *result.Instances[0].InstanceId
	instanceDNS := *result.Instances[0].PrivateDnsName
	instanceIP := *result.Instances[0].PrivateIpAddress

	DebugLogger.Printf("INSTANCE ID: %s\nKEYPAIR ID: %s\n", instanceID, keypairID)

	// We need image info to determine if it is windows or not
	imageInfo, err := client.DescribeImages(context.TODO(), &ec2.DescribeImagesInput{
		ImageIds: []string{*CLI.ami},
	})
	if err != nil {
		log.Printf("WARN: could not retrieve AMI info: %s\n", err)
	}

	tagInput := &ec2.CreateTagsInput{
		Resources: []string{instanceID},
		Tags: []types.Tag{
			{
				Key:   CLI.tagname,
				Value: CLI.tagvalue,
			},
		},
	}

	_, err = client.CreateTags(context.TODO(), tagInput)
	if err != nil {
		return pasdata, fmt.Errorf("got an error tagging the instance: %s", err.Error())
	}

	// pasconf := &ToolshedPASVaultConfig{}
	// CONF.Unmarshal("pasvault", &pasconf)

	// Start populating pasdata
	pasdata.Name = instanceID
	pasdata.SafeName = PASCONF.SafeName

	// default for non-windows AMI's
	pasdata.UserName = "ubuntu"
	pasdata.PlatformID = "UnixSSHKeys"
	pasdata.SecretType = "key"
	pasdata.Secret = privKey

	// Only call GetPasswordData if instance is a windows machine
	if strings.EqualFold(string(imageInfo.Images[0].Platform), string(types.PlatformValuesWindows)) {

		pasdata.UserName = "Administrator"
		pasdata.PlatformID = "WinServerLocal"
		pasdata.SecretType = "password"
		pasdata.Secret = ""

		log.Printf("Waiting for instance, %s, password data to become available.\n", instanceID)

		passwaiter := ec2.NewPasswordDataAvailableWaiter(client)
		maxWaitDur := 600 * time.Second
		err = passwaiter.Wait(context.TODO(),
			&ec2.GetPasswordDataInput{
				InstanceId: &instanceID,
			},
			maxWaitDur,
			func(o *ec2.PasswordDataAvailableWaiterOptions) {
				o.MinDelay = 30 * time.Second
				o.MaxDelay = 90 * time.Second
				o.LogWaitAttempts = true
				o.Retryable = passwordDataAvailableStateRetryable
			})

		if err != nil {
			return pasdata, fmt.Errorf("unable to wait for password data available, %v", err)
		}

		passwordData, err := client.GetPasswordData(context.TODO(), &ec2.GetPasswordDataInput{
			InstanceId: &instanceID,
		})
		if err != nil {
			return pasdata, fmt.Errorf("failed to get password data: %v", err)
		}

		if *passwordData.PasswordData == "" {
			return pasdata, fmt.Errorf("password not available yet")
		}

		password_b64 := *passwordData.PasswordData
		password := DecryptWithPrivateKey([]byte(password_b64), []byte(privKey))

		pasdata.Secret = string(password)
	}

	// Describe the instance to get the public DNS
	describe, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		log.Printf("WARN: could not describe instance: %s", err)
	}
	if len(*describe.Reservations[0].Instances[0].PublicDnsName) > 0 {
		instanceDNS = *describe.Reservations[0].Instances[0].PublicDnsName
		instanceIP = *describe.Reservations[0].Instances[0].PublicIpAddress
	}

	DebugLogger.Printf("InstanceID: %s\nInstanceDNS: %s\nInstanceIP: %s\nPassword: %s\nUser: %s\nPrivate PEM: %s\n", instanceID, instanceDNS, instanceIP, pasdata.Secret, pasdata.UserName, privKey)

	pasdata.Address = instanceDNS

	return pasdata, nil
}

// CreateKeyPair - create a keypair and return the private key
// <https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/ec2-example-working-with-key-pairs.html>
func CreateKeyPair(ec2client ec2.Client, pairName string) (string, string) {

	result, err := ec2client.CreateKeyPair(context.TODO(), &ec2.CreateKeyPairInput{
		KeyName: aws.String(pairName),
	})
	if err != nil {
		log.Printf("Unable to create key pair: %s, %v\n", pairName, err)
		return "", ""
	}

	DebugLogger.Printf("Created key pair %q %s\n%s\n",
		*result.KeyName,
		*result.KeyFingerprint,
		*result.KeyMaterial)

	return *result.KeyPairId, *result.KeyMaterial
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv []byte) []byte {
	out, _ := base64.StdEncoding.DecodeString(string(ciphertext))

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(priv)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
	}

	// Decrypt the data
	//	dec, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, out, nil)
	dec, err := rsa.DecryptPKCS1v15(rand.Reader, key, out)
	if err != nil {
		log.Fatalf("decrypt: %s", err)
	}
	return dec
}

func (c *PASClient) GetSessionToken() (string, error) {

	identurl := fmt.Sprintf("%s/oauth2/platformtoken", c.PASConfig.IDTenantURL) // Use PCloud OAuth

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.PASConfig.User)
	data.Set("client_secret", c.PASConfig.Pass)
	encodedData := data.Encode()

	DebugLogger.Printf("FORM DATA for platform token request: %s\n", encodedData)

	client := GetHTTPClient()

	req, err := http.NewRequest(http.MethodPost, identurl, strings.NewReader(encodedData))
	if err != nil {
		DebugLogger.Fatalf("error in request to get platform token: %s", err.Error())
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(encodedData)))
	response, err := client.Do(req)

	body, e := io.ReadAll(response.Body)
	if e != nil {
		log.Fatalf("error reading platform token response: %s", err.Error())
	}
	defer response.Body.Close()

	// {"error":"string error code","error_description":"short decription goes here"}
	// {"access_token":"xxxxxxxxxx","token_type":"Bearer","expires_in":900}
	var idresp IDTenantResponse
	//var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &idresp)
	if err != nil {
		log.Fatalf("failed to parse json body for platform token: %s\n", err.Error())
	}

	DebugLogger.Printf("ID PLATFORM TOKEN RESPONSE:\n%s\n", string(body))
	return fmt.Sprintf("%s %s", idresp.TokenType, idresp.AccessToken), nil
}

// AddVaultAccount adds the AWS info into the PAS Vault safe
func AddVaultAccount(account *PASAddAccountInput) {
	// var pasvault ToolshedPASVaultConfig
	// CONF.Unmarshal("pasvault", &pasvault)

	client := PASClient{
		BaseURL:      PASCONF.PCloudURL,
		SessionToken: "",
		PASConfig:    PASCONF,
	}
	token, err := client.GetSessionToken()
	if err != nil {
		log.Panicf("failed to get session token: %v", err)
	}
	client.SessionToken = token

	DebugLogger.Printf("PAS Session Token: %s\n", token)

	apps, err := client.AddAccount(account)
	if err != nil {
		log.Fatalf("Failed to add account. %s", err)
	}

	PrintJSON(apps)
}

// AddAccount to CyberArk PAS Vault
func (c *PASClient) AddAccount(account *PASAddAccountInput) (*PASAddAccountOutput, error) {
	url := fmt.Sprintf("%s/passwordvault/api/Accounts", c.BaseURL)
	DebugLogger.Printf("PAS API URL: %s\n", url)

	client := GetHTTPClient()

	content, err := json.Marshal(account)
	if err != nil {
		return &PASAddAccountOutput{}, err
	}

	bodyReader := io.NopCloser(bytes.NewReader(content))

	// create the request
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return &PASAddAccountOutput{}, fmt.Errorf("failed to create new request. %s", err)
	}

	// attach the header
	req.Header = make(http.Header)
	req.Header.Add("Content-Type", "application/json")
	// if token is provided, add header Authorization
	if c.SessionToken != "" {
		req.Header.Add("Authorization", c.SessionToken)
	}

	// send request
	log.Println("Add Account - sending request.")
	res, err := client.Do(req)

	if err != nil {
		return &PASAddAccountOutput{}, fmt.Errorf("failed to send request. %s", err)
	}

	// read response body
	body, error := io.ReadAll(res.Body)
	if error != nil {
		log.Println(error)
	}
	// close response body
	defer res.Body.Close()
	DebugLogger.Printf("Response body after add account request: %s\n", string(body))

	if res.StatusCode >= 300 {
		return &PASAddAccountOutput{}, fmt.Errorf("received non-200 status code '%d'", res.StatusCode)
	}

	GetAccountResponse := &PASAddAccountOutput{}
	err = json.Unmarshal(body, GetAccountResponse)
	return GetAccountResponse, err
}

// -----------------------------------------------------------
// Fetch AWS creds from Conjur using "authn-iam" authenticator

// ConjurAWSIAMAuth struct used to serialize to JSON and post-body to Conjur API /authenticate
type ConjurAWSIAMAuth struct {
	Authorization string `json:"Authorization"`
	Date          string `json:"x-amz-date"`
	Token         string `json:"x-amz-security-token"`
	Host          string `json:"host"`
}

// FetchAWSProviderCredsFromConjur  fetch values from Conjur
func FetchAWSProviderCredsFromConjur() (*AWSProviderCredentials, error) {

	conjconf := &ToolshedConjurConfig{}
	CONF.Unmarshal("conjur", conjconf)

	conjuraccount := conjconf.Account
	conjururl := conjconf.APIURL
	conjauthenticator := conjconf.Authenticator

	key1 := conjconf.AWSProviderAccessKey
	key2 := conjconf.AWSProviderAccessSecret

	awsregion := conjconf.AWSRegion
	awsservice := "sts"
	awshost := fmt.Sprintf("%s.amazonaws.com", awsservice)
	// if awsregion != "us-east-1" {
	// 	awshost = fmt.Sprintf("%s.%s.amazonaws.com", awsservice, awsregion)
	// }
	awspath := "/"
	awsquery := "Action=GetCallerIdentity&Version=2011-06-15"
	awssigningtime := time.Now()
	// Reference - https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15
	awsurl := fmt.Sprintf("https://%s%s?%s", awshost, awspath, awsquery)
	DebugLogger.Printf("AWS STS URL: %s\n", awsurl)

	// These creds are used to connect to Conjur
	awscredprovider := credentials.NewStaticCredentialsProvider(conjconf.AWSAccessKey, conjconf.AWSAccessSecret, "")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(awscredprovider))
	errcheck(err)

	cfg.Region = awsregion

	stsclient := sts.NewFromConfig(cfg)

	assumeroleinput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(conjconf.AWSRoleToAssumeArn),
		RoleSessionName: aws.String("provengine"),
	}
	assumeRoleResp, err := stsclient.AssumeRole(context.TODO(), assumeroleinput)
	errcheck(err)

	sesstokout := assumeRoleResp
	// sessinput := &sts.GetSessionTokenInput{}
	// sesstokout, err := stsclient.GetSessionToken(context.TODO(), sessinput)
	errcheck(err)

	if DEBUG {
		c, err := json.Marshal(sesstokout)
		if err == nil {
			DebugLogger.Printf("STS TOK OUT: %+v\nEND STS TOK OUT\n", string(c))
		}
		errcheck(err)

	}

	req, reqerr := http.NewRequest(http.MethodGet, awsurl, nil)
	errcheck(reqerr)

	// sha256sum of empty string
	emptypayloadhashstring := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Conjur will use these creds to call IAM:GetCallerIdentity
	// Note: MUST use the access key/secret from the response and
	//       NOT the original access key/secret
	awscreds := aws.Credentials{
		AccessKeyID:     *sesstokout.Credentials.AccessKeyId,
		SecretAccessKey: *sesstokout.Credentials.SecretAccessKey,
		SessionToken:    *sesstokout.Credentials.SessionToken,
	}

	mysigner := v4.NewSigner()
	sigerr := mysigner.SignHTTP(context.TODO(), awscreds, req, emptypayloadhashstring, awsservice, awsregion, awssigningtime)
	errcheck(sigerr)

	reqstruct := &ConjurAWSIAMAuth{
		Authorization: req.Header.Get("Authorization"),
		Date:          req.Header.Get("X-Amz-Date"),
		Token:         req.Header.Get("X-Amz-Security-Token"),
		Host:          req.URL.Host,
	}
	reqheadersjson, rherr := json.Marshal(reqstruct)
	errcheck(rherr)

	DebugLogger.Printf("REQ HEADERS: %s\nEND REQ HEADERS\n", reqheadersjson)

	conjidentity := url.QueryEscape(conjconf.Identity)

	// https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Authenticate.htm
	// POST /{authenticator}/{account}/{login}/authenticate
	conjauthurl := fmt.Sprintf("%s/%s/%s/%s/authenticate", conjururl, conjauthenticator, conjuraccount, conjidentity)

	DebugLogger.Printf("CONJ AUTH URL: %s\nEND CONJ AUTH URL\n", conjauthurl)

	// Conjur GO SDK does not support "authn-iam", yet, so, we make a direct REST call here
	reqconj, rcerr := http.NewRequest(http.MethodPost, conjauthurl, bytes.NewBuffer(reqheadersjson))
	errcheck(rcerr)

	reqconj.Header.Add("Content-Type", "application/json")
	reqconj.Header.Add("Accept-Encoding", "base64")

	httpclient := GetHTTPClient()
	resp, err := httpclient.Do(reqconj)
	errcheck(err)

	DebugLogger.Printf("CONJAUTH RESPONSE: %d -- %s\nEND CONJAUTH RESPONSE\n", resp.StatusCode, resp.Status)

	if resp.StatusCode >= 300 {
		os.Exit(1)
	}
	respconjbody, berr := io.ReadAll(resp.Body)
	errcheck(berr)
	defer resp.Body.Close()

	DebugLogger.Printf("CONJUR AUTH RESPONSE: %s\nEND CONJUR AUTH RESPONSE\n", respconjbody)

	// At this point we should have a Conjur session token we can use to fetch the creds
	conjtoken, decerr := b64.StdEncoding.DecodeString(string(respconjbody))
	errcheck(decerr)

	config := conjurapi.Config{
		Account:      conjuraccount,
		ApplianceURL: conjururl,
	}

	conjur, err := conjurapi.NewClientFromToken(config, string(conjtoken))
	errcheck(err)

	// Retrieve a secret into []byte.
	awsproviderkey, err := conjur.RetrieveSecret(key1)
	errcheck(err)

	awsprovidersecret, err := conjur.RetrieveSecret(key2)
	errcheck(err)

	providercreds := AWSProviderCredentials{
		AccessKey:    string(awsproviderkey),
		AccessSecret: string(awsprovidersecret),
	}

	return &providercreds, nil
}

// ----------------------------------------
// Helper functions

func errcheck(err error) {
	if err == nil {
		return
	}
	log.Fatalf("error: %s", err)
}

// helper function to determine if passdata call is retry-able
func passwordDataAvailableStateRetryable(ctx context.Context, input *ec2.GetPasswordDataInput, output *ec2.GetPasswordDataOutput, err error) (bool, error) {
	if err == nil {
		// is this retry-able?
		if len(*output.PasswordData) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// PrintJSON will pretty print any data structure to a JSON blob
func PrintJSON(obj interface{}) error {
	json, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return err
	}

	log.Println(string(json))

	return nil
}

// GetHTTPClient create http client for HTTPS
func GetHTTPClient() *http.Client {
	client := &http.Client{
		Timeout: time.Second * 30,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: TLS_SKIP_VERIFY,
			},
		},
	}
	return client
}
