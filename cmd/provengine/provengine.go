package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Add CLI param fields here, and add processing of params to func ParseParams()
type CLIparams struct {
	name          *string
	value         *string
	keyname       *string
	ami           *string
	debug         *bool
	ver           *bool
	vaultuser     *string
	vaultpass     *string
	vaultbaseurl  *string // ex: "https://somehostname.com"
	vaultsafename *string
	awscredfile   *string
	awsconfigfile *string
}

var (
	version = "dev"
	DEBUG   = false
	CLI     CLIparams
)

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
	CategoryModificationTime  int               `json:"categoryModificationTime"`
	ID                        string            `json:"id"`
	Name                      string            `json:"name"`
	Address                   string            `json:"address"`
	UserName                  string            `json:"userName"`
	PlatformID                string            `json:"platformId"`
	SafeName                  string            `json:"safeName"`
	SecretType                string            `json:"secretType"`
	PlatformAccountProperties map[string]string `json:"platformAccountProperties"`
	SecretManagement          SecretManagement  `json:"secretManagement"`
	CreatedTime               int               `json:"createdTime"`
}

// SecretManagement used in getting and setting accounts
type SecretManagement struct {
	AutomaticManagementEnabled bool   `json:"automaticManagementEnabled"`
	Status                     string `json:"status"`
	ManualManagementReason     string `json:"manualManagementReason,omitempty"`
	LastModifiedTime           int    `json:"lastModifiedTime,omitempty"`
}

func ParseParams() {
	CLI.name = flag.String("n", "", "The name of the tag to attach to the instance")
	CLI.value = flag.String("v", "", "The value of the tag to attach to the instance")
	CLI.keyname = flag.String("k", "", "The name of the keypair to use")
	CLI.ami = flag.String("a", "", "The AMI to use")
	CLI.debug = flag.Bool("d", false, "Enable debug settings")
	CLI.ver = flag.Bool("version", false, "Print version")
	CLI.vaultuser = flag.String("vaultuser", "", "Vault username to use to create session token")
	CLI.vaultpass = flag.String("vaultpass", "", "Vault user's password to use to create session token")
	CLI.vaultbaseurl = flag.String("vaultbaseurl", "", "Vault base url, ex: https://example.com")
	CLI.vaultsafename = flag.String("vaultsafename", "", "Vault safe name where to post the new account info")
	CLI.awscredfile = flag.String("awscredfile", "", "Path to AWS Credentials file; REF: https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html")
	CLI.awsconfigfile = flag.String("awsconfigfile", "", "Path to AWS Config file")
	flag.Parse()

	if *CLI.ver {
		log.Printf("Version: %s\n", version)
		os.Exit(0)
	}

	msg := ""
	if *CLI.vaultuser == "" || *CLI.vaultpass == "" || *CLI.vaultbaseurl == "" {
		msg += "You must supply vault baseurl, user, pass (-vaultuser USER -vaultpas PASS -vaultbaseurl \"HTTPS://EXAMPLE.COM\")"
	}
	if *CLI.vaultsafename == "" {
		msg += "You must supply vault safe name (-vaultsafename \"SAFENAME\")"
	}
	if *CLI.name == "" || *CLI.value == "" {
		msg += "You must supply a name and value for the tag (-n NAME -v VALUE)\n"
	}
	if *CLI.keyname == "" {
		msg += "You must supply a keypair name (-k KEYPAIR-NAME) if not exists, one will be created\n"
	}
	if *CLI.ami == "" {
		msg += "You must supply an AMI name (-a AMI-NAME), ex: -a \"ami-05cc83e573412838f\"\n"
	}
	if *CLI.awscredfile == "" || *CLI.awsconfigfile == "" {
		log.Println("WARN: Both AWS Credential and AWS Config parameters must be set; Using default location, if it exists.")
		log.Println("WARN: Must pass in both params to use AWS cred/config files (-awscredfile \"PATH_TO_AWS_CREDENTIALS\" -awsconfigfile \"PATH_TO_AWS_CONFIG\")")
	}
	if len(msg) > 0 {
		log.Printf("%s\n", msg)
		os.Exit(1)
	}
}

func CreateInstanceCmd() (*PASAddAccountInput, error) {
	DEBUG = *CLI.debug

	pasdata := &PASAddAccountInput{
		Name:       "",
		Address:    "",
		UserName:   "",
		PlatformID: "",
		SafeName:   "",
		SecretType: "",
		Secret:     "",
	}

	log.Printf("Provisioning:\n\tAMI: %s\n\tTAG: %s=%s\n\tKPN: %s\n", *CLI.ami, *CLI.name, *CLI.value, *CLI.keyname)

	var clientLogModeFlags aws.ClientLogMode
	if DEBUG {
		clientLogModeFlags = aws.LogRetries | aws.LogRequest | aws.LogRequestWithBody | aws.LogResponse | aws.LogResponseWithBody | aws.LogDeprecatedUsage | aws.LogRequestEventMessage | aws.LogResponseEventMessage
	}

	var cfg aws.Config
	var err error
	if *CLI.awscredfile != "" && *CLI.awsconfigfile != "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithSharedCredentialsFiles(
				[]string{"test/credentials", "data/credentials"},
			),
			config.WithSharedConfigFiles(
				[]string{"test/config", "data/config"},
			),
			config.WithClientLogMode(clientLogModeFlags))
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithClientLogMode(clientLogModeFlags))
	}

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
				Key:   CLI.name,
				Value: CLI.value,
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
	// Response body after add account request:
	// {"categoryModificationTime":1689351272,
	// "id":"30_11",
	// "name":"i-0f3d81fab06726758",
	// "address":"ec2-35-93-89-92.us-west-2.compute.amazonaws.com",
	// "userName":"ubuntu",
	// "platformId":"UnixSSHKeys",
	// "safeName":"safe1",
	// "secretType":
	// "key","secretManagement":
	// {"automaticManagementEnabled":true,
	// "lastModifiedTime":1689351272},
	// "createdTime":1689351272}

	// jsonString, _ := json.Marshal(body)
	GetAccountResponse := &PASAddAccountOutput{}
	err = json.Unmarshal(body, GetAccountResponse)
	return GetAccountResponse, err
}

func main() {
	ParseParams()
	result, err := CreateInstanceCmd()
	if err != nil {
		log.Printf("ERROR: could not create instance: %s\n", err.Error())
		os.Exit(1)
	}

	log.Printf("RESULT:%+v\n", result)
	AddVaultAccount(result)
}
