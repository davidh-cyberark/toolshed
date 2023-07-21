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
)

var (
	version = "dev"
	DEBUG   = false
	CLI     CLIparams
)

// CLIparams  Add CLI param fields here, and add processing of params to func ParseParams()
type CLIparams struct {
	tagname                   *string // AWS Tag name
	tagvalue                  *string // AWS Tag value
	keyname                   *string // AWS Keypair name to create
	ami                       *string // AMI ID, ex: ami-1234567890
	debug                     *bool   // print extra info to console
	ver                       *bool   // Print Version and exit
	vaultuser                 *string // PAS Vault User
	vaultpass                 *string // PAS Vault Password
	vaultbaseurl              *string // PAS API Base URL
	vaultsafename             *string // PAS Vault Safe name
	awsprovideraccesskey      *string // AWS Access Key
	awsprovideraccesssecret   *string // AWS Access Secret
	awsproviderregion         *string // AWS Region (used only with "awsprovider*" params)
	conjurawsaccesskey        *string // AWS Access Key used to connect to Conjur
	conjurawsaccesssecret     *string // AWS Access Secret used to connect to Conjur
	conjurawsregion           *string // AWS Access Region used to connect to Conjur
	conjurawsaccesskeypath    *string // Conjur path for AWS Access Key
	conjurawsaccesssecretpath *string // Conjur path for AWS Access Secret
	conjurapiurl              *string // Conjur API Url
	conjuraccount             *string // Conjur account name, ex: "conjur"
	conjurauthenticator       *string // Conjur authenticator, ex: "authn-iam/pas-automation"
	conjuridentity            *string // "host/conjur/authn-iam/pas-automation/applications/475601244925/conjur-toolbox"
}

// ParseParams puts cmdline params into CLI var
//
// Usage
//    In order for AWS to be able to create resources, there needs to be at least one set of AWS credentials configured that has permissions to create KeyPair, Add Tags and Run Instances.
//
//    This tool can be used to illustrate 3 scenarios:
//    1. Configure aws-cli with AWS key/secret/region -- the AWS SDK looks for ~/.aws/credentials and ~/.aws/config if key/secret/region are not explicitly set
//
//    2. Pass AWS key/secret/region on the command line -- these creds need to be able to create resources
//       -awsprovideraccesskey    "ABC123"
//       -awsprovideraccesssecret "SECRET"
//       -awsproviderregion       "us-west-2"
//
//    3. Use 2 AWS roles, the first to access Conjur using the AWS IAM Authenticator, and the second (1) stored in Conjur, and (2) has permissions to create resources
//       -conjurawsaccesskey        "ABC123"
//       -conjurawsaccesssecret     "SECRET"
//       -conjurawsregion           "us-west-2"    ### Assume that resources will be created in this Region
//       -conjurawsaccesskeypath    "data/vault/Toolbox-Test/Cloud Service-AWSAccessKeys-toolbox-test/AWSAccessKeyID"
//       -conjurawsaccesssecretpath "data/vault/Toolbox-Test/Cloud Service-AWSAccessKeys-toolbox-test/password"

//
//       The AWS IAM Authenticator <https://docs.conjur.org/Latest/en/Content/Operations/Services/AWS_IAM_Authenticator.htm>

func ParseParams() {
	CLI.tagname = flag.String("n", "", "The name of the tag to attach to the instance")
	CLI.tagvalue = flag.String("v", "", "The value of the tag to attach to the instance")
	CLI.keyname = flag.String("k", "", "The name of the keypair to use")
	CLI.ami = flag.String("a", "", "The AMI to use")
	CLI.debug = flag.Bool("d", false, "Enable debug settings")
	CLI.ver = flag.Bool("version", false, "Print version")

	// PAS Vault
	CLI.vaultuser = flag.String("vaultuser", "", "Vault username to use to create session token")
	CLI.vaultpass = flag.String("vaultpass", "", "Vault user's password to use to create session token")
	CLI.vaultbaseurl = flag.String("vaultbaseurl", "", "Vault base url, ex: https://example.com")
	CLI.vaultsafename = flag.String("vaultsafename", "", "Vault safe name where to post the new account info")

	// (optional) AWS Provider creds
	CLI.awsprovideraccesskey = flag.String("awsprovideraccesskey", "", "AWS Access Key -- with perms to create resources")
	CLI.awsprovideraccesssecret = flag.String("awsprovideraccesssecret", "", "AWS Access Secret")
	CLI.awsproviderregion = flag.String("awsproviderregion", "", "AWS Region")

	// (Optional) Fetch AWS Provider creds from Conjur
	CLI.conjurawsaccesskey = flag.String("conjurawsaccesskey", "", "AWS Access Key to connect to Conjur")
	CLI.conjurawsaccesssecret = flag.String("conjurawsaccesssecret", "", "AWS Access Secret to connect to Conjur")
	CLI.conjurawsregion = flag.String("conjurawsregion", "", "AWS Region to connect to Conjur")
	CLI.conjurawsaccesskeypath = flag.String("conjurawsaccesskeypath", "", "Conjur Path for AWS Access Key")
	CLI.conjurawsaccesssecretpath = flag.String("conjurawsaccesssecretpath", "", "Conjur Path for AWS Access Secret")
	CLI.conjurapiurl = flag.String("conjurapiurl", "", "Conjur API Url")
	CLI.conjuraccount = flag.String("conjuraccount", "", "Conjur account name, ex: \"conjur\"")
	CLI.conjuridentity = flag.String("conjuridentity", "", "Conjur identity")
	CLI.conjurauthenticator = flag.String("conjurauthenticator", "", "Conjur authenticator name")
	flag.Parse()

	DEBUG = *CLI.debug

	if *CLI.ver {
		log.Printf("Version: %s\n", version)
		os.Exit(0)
	}

	msg := ""
	if *CLI.vaultuser == "" || *CLI.vaultpass == "" || *CLI.vaultbaseurl == "" {
		msg += "You must supply vault baseurl, user, pass (-vaultuser USER -vaultpas PASS -vaultbaseurl \"HTTPS://EXAMPLE.COM\")\n"
	}
	if *CLI.vaultsafename == "" {
		msg += "You must supply vault safe name (-vaultsafename \"SAFENAME\")\n"
	}
	if *CLI.tagname == "" || *CLI.tagvalue == "" {
		msg += "You must supply a name and value for the tag (-n NAME -v VALUE)\n"
	}
	if *CLI.keyname == "" {
		msg += "You must supply a keypair name (-k KEYPAIR-NAME) if not exists, one will be created\n"
	}
	if *CLI.ami == "" {
		msg += "You must supply an AMI name (-a AMI-NAME), ex: -a \"ami-05cc83e573412838f\"\n"
	}
	if len(msg) > 0 {
		log.Printf("%s\n", msg)
		os.Exit(1)
	}
}

// PASClient contains the data necessary for requests to pass successfully
type PASClient struct {
	BaseURL      string
	AuthType     string
	InsecureTLS  bool
	SessionToken string
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

// SecretManagement used in getting and setting accounts
type PASSecretManagement struct {
	AutomaticManagementEnabled bool   `json:"automaticManagementEnabled"`
	Status                     string `json:"status"`
	ManualManagementReason     string `json:"manualManagementReason,omitempty"`
	LastModifiedTime           int    `json:"lastModifiedTime,omitempty"`
}

type AWSProviderCredentials struct {
	AccessKey    string
	AccessSecret string
	Region       string
}

// ConjurCreds stores credentials used to interact with Conjur
type ConjurCreds struct {
	AWSCreds                 *AWSProviderCredentials // AWS creds used to authenticate to Conjur
	APIURL                   *string                 // Conjur appliance URL
	Account                  *string                 // Conjur account
	Authenticator            *string                 // Conjur authenticator name, ex "authn-iam/my-iam-conjur-policy-id"
	Identity                 *string                 // Conjur identity, ex "host/conjur/authn-iam/pas-automation/applications/475601244925/conjur-toolbox"
	ProviderAccessKeyPath    *string                 // Conjur path to AWS Provisioner Access key    (needs to be able to create resources)
	ProviderAccessSecretPath *string                 // Conjur path to AWS Provisioner Access secret (needs to be able to create resources)
}

// GetProviderCredentials credentials to enable provider to provision resources
func GetAWSProviderCredentials() (*AWSProviderCredentials, error) {
	if *CLI.conjurapiurl != "" && *CLI.awsproviderregion != "" {
		// assume all the other conjur vars are set
		creds, err := GetAWSProviderCredentialsFromConjur()
		creds.Region = *CLI.awsproviderregion // Provisioner region is different from Conjur AWS Region
		return creds, err
	}

	if *CLI.awsprovideraccesskey != "" {
		// assume all the awsprovider vars are set
		creds := &AWSProviderCredentials{}
		creds.AccessKey = *CLI.awsprovideraccesskey
		creds.AccessSecret = *CLI.awsprovideraccesssecret
		creds.Region = *CLI.awsproviderregion
		return creds, nil
	}

	// Nothing explicit found, so, return nil to indicate we use ~/.aws/credentials
	return nil, nil
}

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

	log.Printf("INSTANCE ID: %s\nKEYPAIR ID: %s\n", instanceID, keypairID)

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

	// Start populating pasdata
	pasdata.Name = instanceID
	pasdata.SafeName = *CLI.vaultsafename

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

	log.Printf("InstanceID: %s\nInstanceDNS: %s\nInstanceIP: %s\nPassword: %s\nUser: %s\nPrivate PEM: %s\n", instanceID, instanceDNS, instanceIP, pasdata.Secret, pasdata.UserName, privKey)

	pasdata.Address = instanceDNS

	return pasdata, nil
}

func passwordDataAvailableStateRetryable(ctx context.Context, input *ec2.GetPasswordDataInput, output *ec2.GetPasswordDataOutput, err error) (bool, error) {
	if err == nil {
		// is this retry-able?
		if len(*output.PasswordData) == 0 {
			return true, nil
		}
	}
	return false, nil
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

	log.Printf("Created key pair %q %s\n%s\n",
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
	/*
		Request:
			POST https://PAS_SERVER/PasswordVault/API/auth/Cyberark/Logon/
			{
				"username":"<user_name>",
				"password":"<password>"
			}
		Response:
			"session token"
	*/

	url := fmt.Sprintf("%s/passwordvault/api/auth/Cyberark/Logon/", c.BaseURL)
	client := GetHTTPClient()

	var bodyReader io.ReadCloser

	content := fmt.Sprintf(`{"username":"%s","password":"%s"}`, *CLI.vaultuser, *CLI.vaultpass)

	bodyReader = io.NopCloser(bytes.NewReader([]byte(content)))

	// create the request
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return "", fmt.Errorf("failed to create new request. %s", err)
	}

	// attach the header
	req.Header = make(http.Header)
	req.Header.Add("Content-Type", "application/json")

	// send request
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request. %s", err)
	}

	// read response body
	body, error := io.ReadAll(res.Body)
	if error != nil {
		fmt.Println(error)
	}
	// close response body
	res.Body.Close()

	return trimQuotes(string(body)), nil
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
	}
	return s
}
func AddVaultAccount(account *PASAddAccountInput) {
	client := PASClient{
		BaseURL:      *CLI.vaultbaseurl,
		InsecureTLS:  true,
		SessionToken: "",
	}
	token, err := client.GetSessionToken()
	if err != nil {
		log.Panicf("failed to get session token: %v", err)
	}
	client.SessionToken = token

	log.Printf("PAS Session Token: %s\n", token)

	apps, err := client.AddAccount(account)
	if err != nil {
		log.Fatalf("Failed to add account. %s", err)
		return
	}

	PrintJSON(apps)
}

// PrintJSON will pretty print any data structure to a JSON blob
func PrintJSON(obj interface{}) error {
	json, err := json.MarshalIndent(obj, "", "    ")
	if err != nil {
		return err
	}

	fmt.Println(string(json))

	return nil
}

func GetHTTPClient() *http.Client {
	client := &http.Client{
		Timeout: time.Second * 30,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	return client
}

// AddAccount to cyberark vault
func (c *PASClient) AddAccount(account *PASAddAccountInput) (*PASAddAccountOutput, error) {
	url := fmt.Sprintf("%s/passwordvault/api/Accounts", c.BaseURL)
	client := GetHTTPClient()

	var bodyReader io.ReadCloser

	content, err := json.Marshal(account)
	if err != nil {
		return &PASAddAccountOutput{}, err
	}

	bodyReader = io.NopCloser(bytes.NewReader(content))

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

	if res.StatusCode >= 300 {
		return &PASAddAccountOutput{}, fmt.Errorf("received non-200 status code '%d'", res.StatusCode)
	}

	// read response body
	body, error := io.ReadAll(res.Body)
	if error != nil {
		fmt.Println(error)
	}
	// close response body
	res.Body.Close()
	log.Printf("Response body after add account request: %s\n", string(body))

	GetAccountResponse := &PASAddAccountOutput{}
	err = json.Unmarshal(body, GetAccountResponse)
	return GetAccountResponse, err
}

func main() {
	ParseParams()
	awscreds, err := GetAWSProviderCredentials()
	result, err := CreateInstanceCmd(awscreds)
	if err != nil {
		log.Printf("ERROR: could not create instance: %s\n", err.Error())
		os.Exit(1)
	}

	log.Printf("RESULT:%+v\n", result)
	AddVaultAccount(result)
}

// ConjurAWSIAMAuth struct used to serialize to JSON and post-body to Conjur API /authenticate
type ConjurAWSIAMAuth struct {
	Authorization string `json:"Authorization"`
	Date          string `json:"x-amz-date"`
	Token         string `json:"x-amz-security-token"`
	Host          string `json:"host"`
}

func errcheck(err error) {
	if err == nil {
		return
	}
	log.Panicf("error: %s", err)
	os.Exit(1)
}

func GetAWSProviderCredentialsFromConjur() (*AWSProviderCredentials, error) {
	creds := &ConjurCreds{
		AWSCreds: &AWSProviderCredentials{
			AccessKey:    *CLI.conjurawsaccesskey,
			AccessSecret: *CLI.conjurawsaccesssecret,
			Region:       *CLI.conjurawsregion,
		},
		APIURL:                   CLI.conjurapiurl,
		Account:                  CLI.conjuraccount,
		Authenticator:            CLI.conjurauthenticator,
		Identity:                 CLI.conjuridentity,
		ProviderAccessKeyPath:    CLI.conjurawsaccesskeypath,
		ProviderAccessSecretPath: CLI.conjurawsaccesssecretpath,
	}
	return FetchAWSProviderCredsFromConjur(creds)
}

// FetchAWSProviderCredsFromConjur using limited scope access key/secret to create session
// token for conjur, and then fetch values from conjur
func FetchAWSProviderCredsFromConjur(conjurcreds *ConjurCreds) (*AWSProviderCredentials, error) {

	conjuraccount := *conjurcreds.Account           // "conjur"
	conjururl := *conjurcreds.APIURL                // "https://cybr-secrets.secretsmgr.cyberark.cloud/api"
	conjauthenticator := *conjurcreds.Authenticator // "authn-iam/pas-automation"

	key1 := *conjurcreds.ProviderAccessKeyPath    // "data/vault/Toolbox-Test/Cloud Service-AWSAccessKeys-toolbox-test/AWSAccessKeyID"
	key2 := *conjurcreds.ProviderAccessSecretPath // "data/vault/Toolbox-Test/Cloud Service-AWSAccessKeys-toolbox-test/password"

	awsregion := conjurcreds.AWSCreds.Region // "us-east-1" Which region is Conjur running in?
	awsservice := "sts"
	awshost := fmt.Sprintf("%s.amazonaws.com", awsservice)
	awspath := "/"
	awsquery := "Action=GetCallerIdentity&Version=2011-06-15"
	awssigningtime := time.Now()
	// Reference - https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15
	awsurl := fmt.Sprintf("https://%s%s?%s", awshost, awspath, awsquery)

	// These creds are used to connect to Conjur
	awscredprovider := credentials.NewStaticCredentialsProvider(conjurcreds.AWSCreds.AccessKey, conjurcreds.AWSCreds.AccessSecret, "")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(awscredprovider))
	errcheck(err)

	cfg.Region = awsregion

	stsclient := sts.NewFromConfig(cfg)

	sessinput := &sts.GetSessionTokenInput{}
	sesstokout, err := stsclient.GetSessionToken(context.TODO(), sessinput)
	errcheck(err)

	if DEBUG {
		c, err := json.Marshal(sesstokout)
		fmt.Printf("STS TOK OUT: %+v\nEND STS TOK OUT\n", string(c))
		errcheck(err)
	}

	req, reqerr := http.NewRequest(http.MethodGet, awsurl, nil)
	errcheck(reqerr)

	emptypayloadhashstring := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256sum of empty string

	// Conjur will use these creds to call IAM:GetCallerIdentity
	// Note: MUST use the access key/secret from the response and NOT the original access key/secret
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

	if DEBUG {
		fmt.Printf("REQ HEADERS: %s\nEND REQ HEADERS\n", reqheadersjson)
	}

	conjidentity := url.QueryEscape(*conjurcreds.Identity)

	// https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Authenticate.htm
	// POST /{authenticator}/{account}/{login}/authenticate
	conjauthurl := fmt.Sprintf("%s/%s/%s/%s/authenticate", conjururl, conjauthenticator, conjuraccount, conjidentity)
	if DEBUG {
		fmt.Printf("CONJ AUTH URL: %s\nEND CONJ AUTH URL\n", conjauthurl)
	}

	// Conjur GO SDK does not support "authn-iam", yet, so, we make a direct REST call here
	reqconj, rcerr := http.NewRequest(http.MethodPost, conjauthurl, bytes.NewBuffer(reqheadersjson))
	errcheck(rcerr)

	reqconj.Header.Add("Content-Type", "application/json")
	reqconj.Header.Add("Accept-Encoding", "base64")
	httpclient := &http.Client{}
	resp, err := httpclient.Do(reqconj)
	errcheck(err)
	if DEBUG {
		fmt.Printf("CONJAUTH RESPONSE: %d -- %s\nEND CONJAUTH RESPONSE\n", resp.StatusCode, resp.Status)
	}
	if resp.StatusCode >= 300 {
		os.Exit(1)
	}
	respconjbody, berr := io.ReadAll(resp.Body)
	errcheck(berr)
	if DEBUG {
		fmt.Printf("CONJUR AUTH RESPONSE: %s\nEND CONJUR AUTH RESPONSE\n", respconjbody)
	}

	defer resp.Body.Close()

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
	// fmt.Println("The secret value is: ", string(awsproviderkey))
	awsprovidersecret, err := conjur.RetrieveSecret(key2)
	errcheck(err)
	// fmt.Println("The secret value is: ", string(awsprovidersecret))
	providercreds := AWSProviderCredentials{
		AccessKey:    string(awsproviderkey),
		AccessSecret: string(awsprovidersecret),
	}

	return &providercreds, nil
}
