package main

import (
	"context"
	"flag"
	"log"
	"strings"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

var (
	version = "dev"
	DEBUG   = false
)

type EC2CreateInstanceAPI interface {
	RunInstances(ctx context.Context,
		params *ec2.RunInstancesInput,
		optFns ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)

	CreateTags(ctx context.Context,
		params *ec2.CreateTagsInput,
		optFns ...func(*ec2.Options)) (*ec2.CreateTagsOutput, error)
}

func MakeInstance(c context.Context, api EC2CreateInstanceAPI, input *ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error) {
	return api.RunInstances(c, input)
}

func MakeTags(c context.Context, api EC2CreateInstanceAPI, input *ec2.CreateTagsInput) (*ec2.CreateTagsOutput, error) {
	return api.CreateTags(c, input)
}

func CreateInstanceCmd() {
	name := flag.String("n", "", "The name of the tag to attach to the instance")
	value := flag.String("v", "", "The value of the tag to attach to the instance")
	keyname := flag.String("k", "", "The name of the keypair to use")
	ami := flag.String("a", "", "The AMI to use")
	debug := flag.Bool("d", false, "Enable debug settings")
	ver := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *ver {
		log.Printf("Version: %s\n", version)
		return
	}

	DEBUG = *debug

	if *name == "" || *value == "" {
		log.Println("You must supply a name and value for the tag (-n NAME -v VALUE)")
		return
	}
	if *keyname == "" {
		log.Println("You must supply a keypair name (-k KEYPAIR-NAME) if not exists, one will be created")
		return
	}
	if *ami == "" {
		log.Println("You must supply an AMI name (-a AMI-NAME), ex: -a \"ami-05cc83e573412838f\"")
		return
	}

	log.Printf("Provisioning:\n\tAMI: %s\n\tTAG: %s=%s\n\tKPN: %s\n", *ami, *name, *value, *keyname)

	clientLogModeFlags := aws.LogRetries
	if *debug {
		clientLogModeFlags = aws.LogRetries | aws.LogRequest | aws.LogRequestWithBody | aws.LogResponse | aws.LogResponseWithBody | aws.LogDeprecatedUsage | aws.LogRequestEventMessage | aws.LogResponseEventMessage
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithClientLogMode(clientLogModeFlags))

	if err != nil {
		panic("configuration error, " + err.Error())
	}

	client := ec2.NewFromConfig(cfg)

	keypairID, privKey := CreateKeyPair(*client, *keyname)
	if privKey == "" {
		log.Println("Failed to create key pair.")
		return
	}

	// Create separate values if required.
	minMaxCount := int32(1)

	input := &ec2.RunInstancesInput{
		ImageId:      aws.String(*ami),
		InstanceType: types.InstanceTypeT3Medium,
		MinCount:     &minMaxCount,
		MaxCount:     &minMaxCount,
		KeyName:      keyname,
	}

	result, err := client.RunInstances(context.TODO(), input)
	if err != nil {
		log.Printf("ERROR: Got an error creating an instance: %s", err)
		return
	}

	imageInfo, err := client.DescribeImages(context.TODO(), &ec2.DescribeImagesInput{
		ImageIds: []string{*ami},
	})
	if err != nil {
		log.Printf("WARN: could not retrieve AMI info: %s\n", err)
	}

	tagInput := &ec2.CreateTagsInput{
		Resources: []string{*result.Instances[0].InstanceId},
		Tags: []types.Tag{
			{
				Key:   name,
				Value: value,
			},
		},
	}

	_, err = MakeTags(context.TODO(), client, tagInput)
	if err != nil {
		log.Println("Got an error tagging the instance:")
		log.Println(err)
		return
	}

	instanceID := *result.Instances[0].InstanceId
	instanceDNS := *result.Instances[0].PrivateDnsName
	instanceIP := *result.Instances[0].PrivateIpAddress

	log.Printf("INSTANCE ID: %s\nKEYPAIR ID: %s\n", instanceID, keypairID)

	// default for non-windows AMI's
	user := "See <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connection-prereqs.html>"
	password := []byte("Use PEM Key")

	// Only call GetPasswordData if instance is a windows machine
	if strings.EqualFold(string(imageInfo.Images[0].Platform), string(types.PlatformValuesWindows)) {

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
			log.Printf("Unable to wait for password data available, %v\n", err)
			return
		}

		passwordData, err := client.GetPasswordData(context.TODO(), &ec2.GetPasswordDataInput{
			InstanceId: &instanceID,
		})
		if err != nil {
			log.Printf("ERROR: failed to get password data: %v\n", err)
			return
		}

		if *passwordData.PasswordData == "" {
			log.Println("Password not available yet.")
			return
		}
		password_b64 := *passwordData.PasswordData
		password = DecryptWithPrivateKey([]byte(password_b64), []byte(privKey))
		if DEBUG {
			log.Printf("Password fetched - (encoded/encrypted string) plaintext.: (%s) %s.\n", password_b64, string(password))
		}
		user = "Administrator (this is the default windows admin user)"
	}

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

	log.Printf("InstanceID: %s\nInstanceDNS: %s\nInstanceIP: %s\nPassword: %s\nUser: %s\nPrivate PEM: %s\n", instanceID, instanceDNS, instanceIP, password, user, privKey)
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

func main() {
	CreateInstanceCmd()
}
