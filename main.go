// This file is part of ffsendr.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var ServiceUrlPattern = regexp.MustCompile(`(https?://.*/)download/([0-9a-f]+)/?(#(.*))?`)

const (
	FirefoxSendService = "https://send.firefox.com/"
	DownloadLimit      = 1
	TimeLimit          = 24 * time.Hour

	WebsocketUrlSuffix = "api/ws"
	WebsocketTimeout   = 5 * time.Second
)

// Metadata about the file
type FileMetadata struct {
	Name     string `json:"name"`
	Size     int    `json:"size"`
	MimeType string `json:"type"`
}

// Metadata sent with each upload
type UploadMetadata struct {
	FileMetadata  FileMetadata `json:"-"`
	DownloadLimit int          `json:"dlimit"`
	TimeLimit     int          `json:"timeLimit"`

	Authorization string `json:"authorization"`
}

// Metadata returned by server after upload
type OwnedFile struct {
	URL        string `json:"url"`
	OwnerToken string `json:"ownerToken"`
	Id         string `json:"id"`
}

// Splits up a given share URL into its various components.
// If baseUrl is empty, it means the parsing failed.
// baseUrl will contain a trailing slash.
func parseShareUrl(url string) (baseUrl, fileId, secret string) {
	urlParts := ServiceUrlPattern.FindStringSubmatch(url)
	if urlParts == nil {
		return
	}

	baseUrl = urlParts[1]
	fileId = urlParts[2]
	secret = urlParts[4]
	return
}

// Construct the websocket URL from the given service base URL.
// The baseUrl is expected to be the one from parseShareUrl.
func makeWebsockUrl(baseUrl string) string {
	l := len(baseUrl)
	if l < 7 {
		return ""
	}

	// make sure the scheme separator is where we expect it to be
	if baseUrl[:4] == "http" && (baseUrl[4:4+3] == "://" || baseUrl[5:5+3] == "://") {
		// then just replace "http" with "ws"
		// works for "https" -> "wss" too
		return "ws" + baseUrl[4:] + WebsocketUrlSuffix
	}

	return ""
}

// Connects to the provided URL to retrieve the server-side challenge.
func getChallenge(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("server returned %s", resp.Status)
	}

	authHdr := resp.Header.Get("WWW-Authenticate")
	if authHdr == "" {
		return "", fmt.Errorf("challenge header not found")
	}

	parts := strings.SplitN(authHdr, " ", 2)
	if parts == nil || parts[0] != "send-v1" {
		return "", fmt.Errorf("unrecognized challenge type: %q", authHdr)
	}
	return parts[1], nil
}

// Downloads the file from the given share URL.
// authKey can be empty if the share URL has a secret appended.
// If both are provided, authKey will take precedence.
// If there are any errors connecting or authenticating to the service,
// err would be non-nil. Otherwise, a ReadCloser (provided by a HTTP
// connection) will be returned. You will need to call Close() after done.
func download(url string, authKey []byte) (io.ReadCloser, error) {
	baseUrl, fileId, secret := parseShareUrl(url)
	if baseUrl == "" {
		return nil, fmt.Errorf("invalid service URL %q", url)
	}

	// if auth key is not provided, try getting it from share URL
	if authKey == nil {
		if secret == "" {
			return nil, fmt.Errorf("no auth key provided")
		}

		keychain, err := NewKeychainFromB64(secret)
		if err != nil {
			return nil, err
		}

		authKey = keychain.authKey
	}

	challenge, err := getChallenge(url)
	if err != nil {
		return nil, err
	} else if challenge == "" {
		return nil, fmt.Errorf("challenge not found")
	}
	auth, err := authenticate(authKey, challenge)
	if err != nil {
		return nil, err
	}

	downloadUrl := fmt.Sprintf("%sapi/download/%s", baseUrl, fileId)
	req, err := http.NewRequest("GET", downloadUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("cant construct download req: %s", err)
	}

	req.Header.Add("Authorization", "send-v1 "+auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cant access download url: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}

	return resp.Body, nil
}

func decryptDownload(filename, outputFilename, key string) error {
	k, err := NewKeychainFromB64(key)
	if err != nil {
		return err
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	s, err := NewDecryptStream(k.masterKey, f)
	if err != nil {
		return err
	}

	f2, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer f2.Close()

	err = s.DecryptStream(f2)
	if err != nil {
		return err
	}

	return nil
}

// Appends a fragment into an already-serialized JSON byte array.
// Note that the fragment should be valid JSON.
// For example, an empty object fragment like `"foo":{}` can be spliced into the
// JSON.
func appendJsonFragment(json []byte, fragment string) []byte {
	// FIXME maybe search for terminating brace instead of assuming?
	if fragment[0] != ',' {
		fragment = "," + fragment
	}
	json = append(json[:len(json)-1], []byte(fragment)...)
	json = append(json, '}')
	return json
}

// Initiates file upload by uploading metadata first.
// Supports only a single file upload (i.e. without a manifest).
// On success, it returns a websocket connection to upload the file data to,
// and the OwnedFile metadata that is returned from the server.
func initUpload(baseUrl string, metadata UploadMetadata, keychain *Keychain) (ownedFile OwnedFile, conn *websocket.Conn, err error) {
	var filesMd, mdJson []byte
	var encMd string

	// ensure base url has trailing slash
	if !strings.HasSuffix(baseUrl, "/") {
		baseUrl += "/"
	}
	wsUrl := makeWebsockUrl(baseUrl)
	if wsUrl == "" {
		err = fmt.Errorf("invalid service URL %q", wsUrl)
		goto end
	}

	// encrypt the UploadMetadata and assemble it into metadata
	filesMd, err = json.Marshal(metadata.FileMetadata)
	if err != nil {
		goto end
	}

	// splice an empty manifest into the JSON
	filesMd = appendJsonFragment(filesMd, `"manifest":{"files":[]}`)

	encMd, err = keychain.EncryptMetadata(string(filesMd))
	if err != nil {
		goto end
	}

	// serialize the upload metadata
	metadata.Authorization = "send-v1 " + keychain.AuthKeyB64()
	mdJson, err = json.Marshal(metadata)
	if err != nil {
		goto end
	}

	// splice the encrypted metadata into the JSON
	mdJson = appendJsonFragment(mdJson, `"fileMetadata":"`+encMd+`"`)

	// connect
	conn, _, err = websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		err = fmt.Errorf("cant connect to %q: %s", wsUrl, err)
		goto end
	}

	// upload metadata
	if err := conn.WriteMessage(websocket.TextMessage, mdJson); err != nil {
		goto end
	}

	// await owner token
	conn.SetReadDeadline(time.Now().Add(WebsocketTimeout))
	err = conn.ReadJSON(&ownedFile)
	if err != nil {
		goto end
	}

end:
	if err != nil && conn != nil {
		conn.Close()
		conn = nil
	}
	return
}

// Uploads the encrypted file blocks to the server using the websocket.
func uploadFileData(conn *websocket.Conn, keychain *Keychain, file io.Reader) error {
	pr, pw := io.Pipe()
	enc, err := NewEncryptStream(keychain.masterKey, nil, ECE_RECORD_SIZE, pw)
	if err != nil {
		return err
	}

	senderErrors := make(chan error)
	go func() {
		buf := make([]byte, enc.RecordSize)
		eof := false
		for !eof {
			n, err := pr.Read(buf)
			if err == io.EOF {
				eof = true
				if n == 0 {
					break
				}
			} else if err != nil {
				senderErrors <- err
				break
			}

			err = conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			if err != nil {
				senderErrors <- err
				break
			}
		}
		close(senderErrors)
	}()

	// write ECE header first
	err = enc.WriteHeader("")
	if err != nil {
		return err
	}

	err = enc.EncryptStream(file)
	if err != nil {
		return err
	}
	pw.Close()

	if err = <-senderErrors; err != nil {
		return err
	}

	// send footer
	err = conn.WriteMessage(websocket.BinaryMessage, []byte{0})
	if err != nil {
		return err
	}

	// wait for server response
	conn.SetReadDeadline(time.Now().Add(WebsocketTimeout))
	reply := struct {
		OK bool `json:"ok"`
	}{}
	err = conn.ReadJSON(&reply)
	if err != nil {
		return err
	} else if !reply.OK {
		return fmt.Errorf("server didn't reply OK")
	}

	return nil
}

func doUpload(filename, serviceUrl string, k *Keychain) (OwnedFile, error) {
	f, err := os.Open(filename)
	if err != nil {
		return OwnedFile{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return OwnedFile{}, err
	}

	_, fname := filepath.Split(filename)
	md := UploadMetadata{
		FileMetadata: FileMetadata{
			fname,
			int(st.Size()),
			"application/octet-stream",
		},

		// these limits are imposed on anonymous users
		// and cant be changed without logging in
		DownloadLimit: DownloadLimit,
		TimeLimit:     int(TimeLimit / time.Second),
	}
	if *verboseArg {
		fmt.Printf("%+v\n", md)
	}

	ownedFile, conn, err := initUpload(serviceUrl, md, k)
	if err != nil {
		return ownedFile, err
	}
	defer conn.Close()

	if *verboseArg {
		fmt.Printf("%+v\n", ownedFile)
	}

	err = uploadFileData(conn, k, f)
	if err != nil {
		return ownedFile, err
	}

	return ownedFile, nil
}

var (
	verboseArg    = flag.Bool("v", false, "More verbose")
	forceArg      = flag.Bool("f", false, "Force overwrite existing files")
	keyArg        = flag.String("key", "", "Secret key")
	authKeyArg    = flag.String("authkey", "", "Auth key for downloading file")
	serviceUrlArg = flag.String("serviceUrl", FirefoxSendService,
		"Service URL")
)

func errorExit(fmtStr string, a ...interface{}) {
	fmt.Printf(fmtStr, a...)
	os.Exit(1)
}

func makeKeychainFromArg() *Keychain {
	if *keyArg == "" {
		errorExit("specify the master key with -key flag")
	}

	k, err := NewKeychainFromB64(*keyArg)
	if err != nil {
		errorExit("invalid key %q: %s", *keyArg, err)
	}

	return k
}

func makeOutputFile(filename string) io.WriteCloser {
	openFlags := os.O_CREATE
	if !*forceArg {
		openFlags |= os.O_EXCL
	}
	f, err := os.OpenFile(filename, openFlags, 0640)
	if err != nil {
		errorExit("cannot create file %q: %s\n", filename, err)
	}

	return f
}

func showUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), `
Usage: %[1]s [-f | options...] <action> <action args...>

Actions:
    - download     Downloads a file
    - upload       Uploads a file
    - decrypt      Decrypts a downloaded file
    - keys         Compute sub-keys from secret

Examples
=========

  Download: %[1]s [-f | -authkey xxx...] download https://....

  Upload:   %[1]s [-serviceUrl ... | -key ...] upload <filename>

  Decrypt:  %[1]s -key ... decrypt <filename>

  Keys:     %[1]s -key ... keys


Following global options are shared among the actions above:

`, os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = showUsage

	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var err error

	action := flag.Arg(0)
	switch action {
	case "upload":
		filename := flag.Arg(1)
		if filename == "" {
			errorExit("please specify filename to upload\n")
		}

		var k *Keychain
		if *keyArg == "" {
			k, err = NewKeychainFromRand()
		} else {
			k, err = NewKeychainFromB64(*keyArg)
		}

		if err != nil {
			errorExit("%s\n", err)
		}

		ownedFile, err := doUpload(filename, *serviceUrlArg, k)
		if err != nil {
			errorExit("cannot upload: %s\n", err)
		}

		fmt.Printf("file uploaded\nURL: %s#%s\n",
			ownedFile.URL, k.MasterKeyB64())

	case "download":
		url := flag.Arg(1)

		var k *Keychain
		baseUrl, fileId, secretKey := parseShareUrl(url)
		if baseUrl == "" {
			errorExit("invalid URL %s\n", url)
		}

		// validate secret key as early as possible
		if secretKey != "" {
			k, err = NewKeychainFromB64(secretKey)
			if err != nil {
				errorExit("secret key %q is invalid: %s\n", secretKey, err)
			}
		}

		filename := fileId + ".bin"
		f := makeOutputFile(filename)
		defer f.Close()

		var authKey []byte
		if *authKeyArg != "" {
			authKey, err = base64.RawURLEncoding.DecodeString(*authKeyArg)
			if err != nil || len(authKey) != 64 {
				errorExit("invalid auth key")
			}
		}

		r, err := download(url, authKey)
		if err != nil {
			errorExit("cannot download: %s\n", err)
		}
		defer r.Close()

		if k != nil {
			s, err := NewDecryptStream(k.masterKey, r)
			err = s.DecryptStream(f)
			if err != nil {
				errorExit("unable to decrypt: %s\n", err)
			}
		} else {
			_, err = io.Copy(f, r)
			if err != nil {
				errorExit("unable to download: %s\n", err)
			}
		}

		fmt.Printf("downloaded successfully %s\n", filename)
		if k == nil {
			fmt.Println("no secret key was provided; decrypt the file manually.")
		}

	case "decrypt":
		k := makeKeychainFromArg()

		filename := flag.Arg(1)
		inFile, err := os.Open(filename)
		if err != nil {
			errorExit("unable to open %q: %s\n", filename, err)
		}
		defer inFile.Close()

		outFile := makeOutputFile(filename + ".dec")
		defer outFile.Close()

		s, err := NewDecryptStream(k.masterKey, inFile)
		err = s.DecryptStream(outFile)
		if err != nil {
			errorExit("unable to decrypt: %s\n", err)
		}

		fmt.Printf("file decrypted successfully: %q\n", filename)

	case "keys":
		k := makeKeychainFromArg()
		k.Dump()
		fmt.Printf("auth key (b64): %s\n", k.AuthKeyB64())

	default:
		fmt.Printf("unknown action %q\n", action)
		flag.Usage()
		os.Exit(2)
	}
}
