package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// bucketCreds holds locally-stored credentials for a bucket.
type bucketCreds struct {
	Name       string `json:"name"`
	Endpoint   string `json:"endpoint"`
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	BucketName string `json:"bucket_name"`
}

func credsFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".everywhere", "buckets.json")
}

func loadBucketCreds() (map[string]*bucketCreds, error) {
	data, err := os.ReadFile(credsFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*bucketCreds), nil
		}
		return nil, err
	}
	var creds map[string]*bucketCreds
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return creds, nil
}

func saveBucketCreds(creds map[string]*bucketCreds) error {
	path := credsFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func storeBucketCreds(bkt *bucketItem) error {
	creds, err := loadBucketCreds()
	if err != nil {
		return err
	}
	bucketName := bkt.S3Bucket
	if bucketName == "" {
		bucketName = bkt.Name
	}
	creds[bkt.Name] = &bucketCreds{
		Name:       bkt.Name,
		Endpoint:   bkt.S3Endpoint,
		AccessKey:  bkt.AccessKey,
		SecretKey:  bkt.SecretKey,
		BucketName: bucketName,
	}
	return saveBucketCreds(creds)
}

func removeBucketCreds(name string) {
	creds, err := loadBucketCreds()
	if err != nil {
		return
	}
	delete(creds, name)
	_ = saveBucketCreds(creds)
}

func getBucketCreds(name string) (*bucketCreds, error) {
	creds, err := loadBucketCreds()
	if err != nil {
		return nil, err
	}
	c, ok := creds[name]
	if !ok {
		return nil, fmt.Errorf("no stored credentials for bucket %q — credentials are only saved at creation time", name)
	}
	return c, nil
}

func newS3Client(creds *bucketCreds) *s3.Client {
	return s3.New(s3.Options{
		BaseEndpoint: aws.String(creds.Endpoint),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(creds.AccessKey, creds.SecretKey, ""),
		UsePathStyle: true,
	})
}

func s3ListObjects(ctx context.Context, client *s3.Client, bucket, prefix string) error {
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list objects: %w", err)
		}
		for _, obj := range page.Contents {
			size := aws.ToInt64(obj.Size)
			modified := obj.LastModified.Format("2006-01-02 15:04:05")
			fmt.Printf("%s  %10d  %s\n", modified, size, aws.ToString(obj.Key))
		}
	}
	return nil
}

func s3Upload(ctx context.Context, client *s3.Client, bucket, key, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          f,
		ContentLength: aws.Int64(info.Size()),
	})
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	fmt.Printf("uploaded %s → %s (%d bytes)\n", localPath, key, info.Size())
	return nil
}

func s3Download(ctx context.Context, client *s3.Client, bucket, key, localPath string) error {
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	f, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("downloaded %s → %s (%d bytes)\n", key, localPath, n)
	return nil
}

func s3Delete(ctx context.Context, client *s3.Client, bucket, key string) error {
	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	fmt.Printf("deleted %s\n", key)
	return nil
}

// parseCpArgs parses `cp` arguments into (bucket, key, localPath, isUpload).
// Upload:   cp local-file bucket:key
// Download: cp bucket:key local-file
func parseCpArgs(src, dst string) (bucket, key, localPath string, isUpload bool, err error) {
	srcBucket, srcKey := splitBucketKey(src)
	dstBucket, dstKey := splitBucketKey(dst)

	if srcBucket != "" && dstBucket != "" {
		return "", "", "", false, fmt.Errorf("cannot copy between two buckets — use a local path for one side")
	}
	if srcBucket == "" && dstBucket == "" {
		return "", "", "", false, fmt.Errorf("one argument must be a bucket reference (bucket:key)")
	}

	if dstBucket != "" {
		// Upload: local → bucket
		key := dstKey
		if key == "" {
			key = filepath.Base(src)
		}
		return dstBucket, key, src, true, nil
	}

	// Download: bucket → local
	localPath = dst
	if localPath == "" || localPath == "." {
		parts := strings.Split(srcKey, "/")
		localPath = parts[len(parts)-1]
	}
	return srcBucket, srcKey, localPath, false, nil
}

// splitBucketKey splits "bucket:key" into (bucket, key).
// Returns ("", "") if not a bucket reference.
func splitBucketKey(s string) (string, string) {
	// Don't treat Windows paths like C:\file as bucket refs
	if len(s) == 2 && s[1] == ':' {
		return "", ""
	}
	if i := strings.IndexByte(s, ':'); i > 0 {
		return s[:i], s[i+1:]
	}
	return "", ""
}
