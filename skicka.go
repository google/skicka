//
// skicka.go
// Copyright(c)2014-2015 Google, Inc.
//
// Tool for transferring files to/from Google Drive and related operations.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bytes"
	"code.google.com/p/gcfg"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/skicka/gdrive"
	"google.golang.org/api/drive/v2"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const timeFormat = "2006-01-02T15:04:05.000000000Z07:00"
const encryptionSuffix = ".aes256"
const resumableUploadMinSize = 64 * 1024 * 1024
const passphraseEnvironmentVariable = "SKICKA_PASSPHRASE"

///////////////////////////////////////////////////////////////////////////
// Global Variables

type debugging bool

var (
	gd *gdrive.GDrive

	// The key is only set if encryption is needed (i.e. if -encrypt is
	// provided for an upload, or if an encrypted file is encountered
	// during 'download' or 'cat').
	key []byte

	debug   debugging
	verbose debugging

	// Configuration read in from the skicka config file.
	config struct {
		Google struct {
			ClientId     string
			ClientSecret string
			// If set, is appended to all http requests via ?key=XXX.
			ApiKey string
		}
		Encryption struct {
			Salt             string
			Passphrase_hash  string
			Encrypted_key    string
			Encrypted_key_iv string
		}
		Upload struct {
			Ignored_Regexp         []string
			Bytes_per_second_limit int
		}
		Download struct {
			Bytes_per_second_limit int
		}
	}

	// Various statistics gathered along the way. These all should be
	// updated using atomic operations since we often have multiple threads
	// working concurrently for uploads and downloads.
	stats struct {
		DiskReadBytes     int64
		DiskWriteBytes    int64
		UploadBytes       int64
		DownloadBytes     int64
		LocalFilesUpdated int64
		DriveFilesUpdated int64
	}
)

///////////////////////////////////////////////////////////////////////////
// Utility types

var authre = regexp.MustCompile("Authorization: Bearer [^\\s]*")

// sanitize attempts to remove sensitive values like authorization key
// values from debugging output so that it can be shared without also
// compromising the login credentials, etc.
func sanitize(s string) string {
	if config.Google.ClientId != "" {
		s = strings.Replace(s, config.Google.ClientId, "[***ClientId***]", -1)
	}
	if config.Google.ClientSecret != "" {
		s = strings.Replace(s, config.Google.ClientSecret, "[***ClientSecret***]", -1)
	}
	if config.Google.ApiKey != "" {
		s = strings.Replace(s, config.Google.ApiKey, "[***ApiKey***]", -1)
	}
	s = authre.ReplaceAllLiteralString(s, "Authorization: Bearer [***AuthToken***]")
	return s
}

func debugNoPrint(s string, args ...interface{}) {
}

func debugPrint(s string, args ...interface{}) {
	debug.Printf(s, args...)
}

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Print(sanitize(fmt.Sprintf(format, args...)))
	}
}

// fileCloser is kind of a hack: it implements the io.ReadCloser
// interface, wherein the Read() calls go to R, and the Close() call
// goes to C.
type fileCloser struct {
	R io.Reader
	C *os.File
}

func (fc *fileCloser) Read(b []byte) (int, error) {
	return fc.R.Read(b)
}

func (fc *fileCloser) Close() error {
	return fc.C.Close()
}

///////////////////////////////////////////////////////////////////////////
// Small utility functions

// Utility function to decode hex-encoded bytes; treats any encoding errors
// as fatal errors (we assume that checkConfigValidity has already made
// sure the strings in the config file are reasonable.)
func decodeHexString(s string) []byte {
	r, err := hex.DecodeString(s)
	checkFatalError(err, "unable to decode hex string")
	return r
}

// Returns a string that gives the given number of bytes with reasonable
// units. If 'fixedWidth' is true, the returned string will always be the same
// length, which makes it easier to line things up in columns.
func fmtbytes(n int64, fixedWidth bool) string {
	if fixedWidth {
		if n >= 1024*1024*1024*1024 {
			return fmt.Sprintf("%6.2f TiB", float64(n)/(1024.*1024.*
				1024.*1024.))
		} else if n >= 1024*1024*1024 {
			return fmt.Sprintf("%6.2f GiB", float64(n)/(1024.*1024.*
				1024.))
		} else if n > 1024*1024 {
			return fmt.Sprintf("%6.2f MiB", float64(n)/(1024.*1024.))
		} else if n > 1024 {
			return fmt.Sprintf("%6.2f kiB", float64(n)/1024.)
		} else {
			return fmt.Sprintf("%6d B  ", n)
		}
	} else {
		if n >= 1024*1024*1024*1024 {
			return fmt.Sprintf("%.2f TiB", float64(n)/(1024.*1024.*
				1024.*1024.))
		} else if n >= 1024*1024*1024 {
			return fmt.Sprintf("%.2f GiB", float64(n)/(1024.*1024.*
				1024.))
		} else if n > 1024*1024 {
			return fmt.Sprintf("%.2f MiB", float64(n)/(1024.*1024.))
		} else if n > 1024 {
			return fmt.Sprintf("%.2f kiB", float64(n)/1024.)
		} else {
			return fmt.Sprintf("%d B", n)
		}
	}
}

func fmtDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	var str string
	if hours > 0 {
		str += fmt.Sprintf("%dh ", hours)
	}
	if minutes > 0 {
		str += fmt.Sprintf("%dm ", minutes)
	}
	return str + fmt.Sprintf("%ds", seconds%60)
}

// A few values that printFinalStats() uses to do its work
var startTime = time.Now()
var syncStartTime time.Time
var statsMutex sync.Mutex
var lastStatsTime = time.Now()
var lastStatsBytes int64
var maxActiveBytes int64

func updateActiveMemory() {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	var memstats runtime.MemStats
	runtime.ReadMemStats(&memstats)
	activeBytes := int64(memstats.Alloc)
	if activeBytes > maxActiveBytes {
		maxActiveBytes = activeBytes
	}
}

// Called to print overall statistics after an upload or download is finished.
func printFinalStats() {
	updateActiveMemory()

	statsMutex.Lock()
	defer statsMutex.Unlock()

	syncTime := time.Now().Sub(syncStartTime)
	fmt.Printf("skicka: Preparation time %s, sync time %s\n",
		fmtDuration(syncStartTime.Sub(startTime)), fmtDuration(syncTime))
	fmt.Printf("skicka: Updated %d Drive files, %d local files\n",
		stats.DriveFilesUpdated, stats.LocalFilesUpdated)
	fmt.Printf("skicka: %s read from disk, %s written to disk\n",
		fmtbytes(stats.DiskReadBytes, false),
		fmtbytes(stats.DiskWriteBytes, false))
	fmt.Printf("skicka: %s uploaded (%s/s), %s downloaded (%s/s)\n",
		fmtbytes(stats.UploadBytes, false),
		fmtbytes(int64(float64(stats.UploadBytes)/syncTime.Seconds()),
			false),
		fmtbytes(stats.DownloadBytes, false),
		fmtbytes(int64(float64(stats.DownloadBytes)/syncTime.Seconds()),
			false))
	fmt.Printf("skicka: %s peak memory used\n",
		fmtbytes(maxActiveBytes, false))
}

// Return the MD5 hash of the file at the given path in the form of a
// string. If encryption is enabled, use the encrypted file contents when
// computing the hash.
func localFileMD5Contents(path string, encrypt bool, iv []byte) (string, error) {
	contentsReader, _, err := getFileContentsReaderForUpload(path, encrypt, iv)
	if contentsReader != nil {
		defer contentsReader.Close()
	}
	if err != nil {
		return "", err
	}

	md5 := md5.New()
	n, err := io.Copy(md5, contentsReader)
	atomic.AddInt64(&stats.DiskReadBytes, n)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", md5.Sum(nil)), nil
}

// Returns an io.ReadCloser for given file, such that the bytes read are
// ready for upload: specifically, if encryption is enabled, the contents
// are encrypted with the given key and the initialization vector is
// prepended to the returned bytes. Otherwise, the contents of the file are
// returned directly.
func getFileContentsReaderForUpload(path string, encrypt bool,
	iv []byte) (io.ReadCloser, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return f, 0, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	fileSize := stat.Size()

	if encrypt {
		if key == nil {
			key = decryptEncryptionKey()
		}

		r := makeEncrypterReader(key, iv, f)

		// Prepend the initialization vector to the returned bytes.
		r = io.MultiReader(bytes.NewReader(iv[:aes.BlockSize]), r)

		return &fileCloser{R: r, C: f}, fileSize + aes.BlockSize, nil
	}
	return f, fileSize, nil
}

func pathSeparator() string {
	if runtime.GOOS == "windows" {
		return "\\"
	} else {
		return "/"
	}
}

///////////////////////////////////////////////////////////////////////////
// Encryption/decryption

// Encrypt the given plaintext using the given encryption key 'key' and
// initialization vector 'iv'. The initialization vector should be 16 bytes
// (the AES block-size), and should be randomly generated and unique for
// each file that's encrypted.
func encryptBytes(key []byte, iv []byte, plaintext []byte) []byte {
	r, _ := ioutil.ReadAll(makeEncrypterReader(key, iv, bytes.NewReader(plaintext)))
	return r
}

// Returns an io.Reader that encrypts the byte stream from the given io.Reader
// using the given key and initialization vector.
func makeEncrypterReader(key []byte, iv []byte, reader io.Reader) io.Reader {
	if key == nil {
		printErrorAndExit(fmt.Errorf("uninitialized key in makeEncrypterReader()"))
	}
	block, err := aes.NewCipher(key)
	checkFatalError(err, "unable to create AES cypher")

	if len(iv) != aes.BlockSize {
		printErrorAndExit(fmt.Errorf("IV length %d != aes.BlockSize %d", len(iv),
			aes.BlockSize))
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	return &cipher.StreamReader{S: stream, R: reader}
}

// Decrypt the given cyphertext using the given encryption key and
// initialization vector 'iv'.
func decryptBytes(key []byte, iv []byte, ciphertext []byte) []byte {
	r, _ := ioutil.ReadAll(makeDecryptionReader(key, iv, bytes.NewReader(ciphertext)))
	return r
}

func makeDecryptionReader(key []byte, iv []byte, reader io.Reader) io.Reader {
	if key == nil {
		printErrorAndExit(fmt.Errorf("uninitialized key in makeDecryptionReader()"))
	}
	block, err := aes.NewCipher(key)
	checkFatalError(err, "unable to create AES cypher")

	if len(iv) != aes.BlockSize {
		printErrorAndExit(fmt.Errorf("IV length %d != aes.BlockSize %d", len(iv),
			aes.BlockSize))
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	return &cipher.StreamReader{S: stream, R: reader}
}

// Return the given number of bytes of random values, using a
// cryptographically-strong random number source.
func getRandomBytes(n int) []byte {
	bytes := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, bytes)
	checkFatalError(err, "unable to get random bytes")
	return bytes
}

// Create a new encryption key and encrypt it using the user-provided
// passphrase. Prints output to stdout that gives text to add to the
// ~/.skicka.config file to store the encryption key.
func generateKey() {
	passphrase := os.Getenv(passphraseEnvironmentVariable)
	if passphrase == "" {
		printErrorAndExit(fmt.Errorf(passphraseEnvironmentVariable +
			" environment variable not set."))
	}

	// Derive a 64-byte hash from the passphrase using PBKDF2 with 65536
	// rounds of SHA256.
	salt := getRandomBytes(32)
	hash := pbkdf2.Key([]byte(passphrase), salt, 65536, 64, sha256.New)
	if len(hash) != 64 {
		printErrorAndExit(fmt.Errorf("incorrect key size returned by pbkdf2 %d", len(hash)))
	}

	// We'll store the first 32 bytes of the hash to use to confirm the
	// correct passphrase is given on subsequent runs.
	passHash := hash[:32]
	// And we'll use the remaining 32 bytes as a key to encrypt the actual
	// encryption key. (These bytes are *not* stored).
	keyEncryptKey := hash[32:]

	// Generate a random encryption key and encrypt it using the key
	// derived from the passphrase.
	key := getRandomBytes(32)
	iv := getRandomBytes(16)
	encryptedKey := encryptBytes(keyEncryptKey, iv, key)

	fmt.Printf("; Add the following lines to the [encryption] section\n")
	fmt.Printf("; of your ~/.skicka.config file.\n")
	fmt.Printf("\tsalt=%s\n", hex.EncodeToString(salt))
	fmt.Printf("\tpassphrase-hash=%s\n", hex.EncodeToString(passHash))
	fmt.Printf("\tencrypted-key=%s\n", hex.EncodeToString(encryptedKey))
	fmt.Printf("\tencrypted-key-iv=%s\n", hex.EncodeToString(iv))
}

// Decrypts the encrypted encryption key using values from the config file
// and the user's passphrase.
func decryptEncryptionKey() []byte {
	if key != nil {
		panic("key aready decrypted!")
	}

	salt := decodeHexString(config.Encryption.Salt)
	passphraseHash := decodeHexString(config.Encryption.Passphrase_hash)
	encryptedKey := decodeHexString(config.Encryption.Encrypted_key)
	encryptedKeyIv := decodeHexString(config.Encryption.Encrypted_key_iv)

	passphrase := os.Getenv(passphraseEnvironmentVariable)
	if passphrase == "" {
		fmt.Fprintf(os.Stderr, "skicka: "+passphraseEnvironmentVariable+
			" environment variable not set")
		os.Exit(1)
	}

	derivedKey := pbkdf2.Key([]byte(passphrase), salt, 65536, 64, sha256.New)
	// Make sure the first 32 bytes of the derived key match the bytes stored
	// when we first generated the key; if they don't, the user gave us
	// the wrong passphrase.
	if !bytes.Equal(derivedKey[:32], passphraseHash) {
		fmt.Fprintf(os.Stderr, "skicka: incorrect passphrase")
		os.Exit(1)
	}

	// Use the last 32 bytes of the derived key to decrypt the actual
	// encryption key.
	keyEncryptKey := derivedKey[32:]
	return decryptBytes(keyEncryptKey, encryptedKeyIv, encryptedKey)
}

///////////////////////////////////////////////////////////////////////////
// Google Drive utility functions

// Returns the initialization vector (for encryption) for the given file.
// We store the initialization vector as a hex-encoded property in the
// file so that we don't need to download the file's contents to find the
// IV.
func getInitializationVector(driveFile *drive.File) ([]byte, error) {
	ivhex, err := gdrive.GetProperty(driveFile, "IV")
	if err != nil {
		return nil, err
	}
	iv, err := hex.DecodeString(ivhex)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("unexpected length of IV %d", len(iv))
	}
	return iv, nil
}

func getPermissions(driveFile *drive.File) (os.FileMode, error) {
	permStr, err := gdrive.GetProperty(driveFile, "Permissions")
	if err != nil {
		return 0, err
	}
	perm, err := strconv.ParseInt(permStr, 8, 16)
	return os.FileMode(perm), err
}

///////////////////////////////////////////////////////////////////////////
// Error handling

func checkFatalError(err error, message string) {
	if err != nil {
		if message != "" {
			printErrorAndExit(fmt.Errorf("%s: %v", message, err))
		} else {
			printErrorAndExit(err)
		}
	}
}

func addErrorAndPrintMessage(totalErrors *int32, message string, err error) {
	fmt.Fprintf(os.Stderr, "skicka: "+message+": %s\n", err)
	atomic.AddInt32(totalErrors, 1)
}

func printErrorAndExit(err error) {
	fmt.Fprintf(os.Stderr, "\rskicka: %s\n", err)
	os.Exit(1)
}

func printUsageAndExit() {
	usage()
	os.Exit(1)
}

///////////////////////////////////////////////////////////////////////////
// main (and its helpers)

// Create an empty configuration file for the user to use as a starting-point.
func createConfigFile(filename string) {
	contents := `; Default .skicka.config file. See 
; https://github.com/google/skicka/blob/master/README.md for more
; information about setting up skicka.
[google]
	clientid=YOUR_GOOGLE_APP_CLIENT_ID
	clientsecret=YOUR_GOOGLE_APP_SECRET
    ;An API key may optionally be provided.
    ;apikey=YOUR_API_KEY
[encryption]
        ; Run 'skicka genkey' to generate an encyption key.
	;salt=
	;passphrase-hash=
	;encrypted-key=
	;encrypted-key-iv=
[upload]
	; You may want to specify regular expressions to match local filenames
	; that you want to be ignored by 'skicka upload'. Use one ignored-regexp
        ; line for each such regular expression.
	;ignored-regexp="\\.o$"
	;ignored-regexp=~$
	;
	; To limit upload bandwidth, you can set the maximum (average)
	; bytes per second that will be used for uploads
	;bytes-per-second-limit=524288  ; 512kB
`
	// Don't overwrite an already-existing configuration file.
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		err := ioutil.WriteFile(filename, []byte(contents), 0600)
		if err != nil {
			printErrorAndExit(fmt.Errorf("%s: %v", filename, err))
		}
		fmt.Printf("skicka: created configuration file %s.\n", filename)
	} else {
		printErrorAndExit(fmt.Errorf("%s: file already exists; "+
			"leaving it alone.", filename))
	}
}

func checkEncryptionConfig(value string, name string, bytes int) int {
	if value == "" {
		return 0
	}
	if num, err := hex.DecodeString(value); err != nil || len(num) != bytes {
		fmt.Fprintf(os.Stderr, "skicka: missing or invalid "+
			"[encryption]/%s value (expecting %d hex "+
			"characters).\n", name, 2*bytes)
		return 1
	}
	return 0
}

// Check that the configuration read from the config file isn't obviously
// missing needed entries so that we can give better error messages at startup
// while folks are first getting things setup.
func checkConfigValidity() {
	nerrs := 0
	if config.Google.ClientId == "" ||
		config.Google.ClientId == "YOUR_GOOGLE_APP_CLIENT_ID" {
		fmt.Fprintf(os.Stderr, "skicka: missing [google]/clientid in "+
			"configuration file.\n")
		nerrs++
	}
	if config.Google.ClientSecret == "" ||
		config.Google.ClientSecret == "YOUR_GOOGLE_APP_SECRET" {
		fmt.Fprintf(os.Stderr, "skicka: missing [google]/clientsecret in "+
			"configuration file.\n")
		nerrs++
	}

	// It's ok if the encryption stuff isn't present (if encryption
	// isn't being used), but if it is present, it must be valid...
	nerrs += checkEncryptionConfig(config.Encryption.Salt, "salt", 32)
	nerrs += checkEncryptionConfig(config.Encryption.Passphrase_hash,
		"passphrase-hash", 32)
	nerrs += checkEncryptionConfig(config.Encryption.Encrypted_key,
		"encrypted-key", 32)
	nerrs += checkEncryptionConfig(config.Encryption.Encrypted_key_iv,
		"encrypted-key-iv", 16)

	if nerrs > 0 {
		os.Exit(1)
	}
}

func readConfigFile(filename string) {
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filename); err != nil {
			printErrorAndExit(fmt.Errorf("%s: %v", filename, err))
		} else if goperms := info.Mode() & ((1 << 6) - 1); goperms != 0 {
			printErrorAndExit(fmt.Errorf("%s: permissions of configuration file "+
				"allow group/other access. Your secrets are at risk.",
				filename))
		}
	}

	err := gcfg.ReadFileInto(&config, filename)
	if err != nil {
		printErrorAndExit(fmt.Errorf("%s: %v. (You may want to run \"skicka "+
			"init\" to create an initial configuration file.)", filename, err))
	}
	checkConfigValidity()
}

func usage() {
	fmt.Printf(
		`skicka is a tool for working with files and folders on Google Drive.
See http://github.com/google/skicka/README.md for information about getting started.

usage: skicka [common options] <command> [command options]

Commands and their options are:
  cat        Print the contents of the Google Drive file to standard output.
             Arguments: drive_path ...

  download   Recursively download either a single file, or all files from a
             Google Drive folder to a local directory. If the corresponding
             local file already exists and has the same contents as the its
             Google Drive file, the download is skipped.
             Arguments: [-ignore-times] drive_path local_path

  du         Print the space used by the Google Drive folder and its children.
             Arguments: [drive_path ...]

  help       Print this help text.

  genkey     Generate a new key for encrypting files.

  init       Create an initial ~/.skicka.config configuration file. (You
             will need to edit it before using skicka; see comments in the
             configuration file for details.)

  ls         List the files and directories in the given Google Drive folder.
             Arguments: [-l, -ll, -r] [drive_path ...],
             where -l and -ll specify long (including sizes and update times)
             and really long output (also including MD5 checksums), respectively.
             The -r argument causes ls to recursively list all files in the
             hierarchy rooted at the base directory.

  mkdir      Create a new directory (folder) at the given Google Drive path.
             Arguments: [-p] drive_path ...,
             where intermediate directories in the path are created if -p is
             specified.

  rm	     Remove a file or directory at the given Google Drive path.
             Arguments: [-r, -s] drive_path ...,
             where files and directories are recursively removed if -r is specified
             and the google drive trash is skipped if -s is specified. The default 
             behavior is to fail if the drive path specified is a directory and -r is
             not specified, and to send files to the trash instead of permanently
             deleting them.

  upload     Uploads all files in the local directory and its children to the
             given Google Drive path. Skips files that have already been
             uploaded.
             Arguments: [-ignore-times] [-encrypt] local_path drive_path

Options valid for both "upload" and "download":
  -ignore-times    Normally, skicka assumes that if the timestamp of a local file
                   matches the timestamp of the file on Drive and the files have
                   the same size, then it isn't necessary to confirm that the
                   file contents match. The -ignore-times flag can be used to
                   force checking file contents in this case.

General options valid for all commands:
  -config=<filename>     Specify a configuration file. Default: ~/.skicka.config.
  -debug                 Enable debugging output.
  -dump-http             Dump http traffic.
  -tokencache=<filename> OAuth2 token cache file. Default: ~/.skicka.tokencache.json.
  -verbose               Enable verbose output.
`)
}

func shortUsage() {
	fmt.Fprintf(os.Stderr, "usage: skicka "+
		"[cat,download,du,genkey,help,init,ls,mkdir,rm,upload] ...\n")
	fmt.Fprintf(os.Stderr, "Run \"skicka help\" for more detailed help text.\n")
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func main() {
	home := userHomeDir()
	cachefile := flag.String("tokencache", home+"/.skicka.tokencache.json",
		"OAuth2 token cache file")
	configFilename := flag.String("config", home+"/.skicka.config",
		"Configuration file")
	vb := flag.Bool("verbose", false, "Enable verbose output")
	dbg := flag.Bool("debug", false, "Enable debugging output")
	dumpHttp := flag.Bool("dump-http", false, "Dump http traffic")
	flag.Usage = usage
	flag.Parse()

	if len(flag.Args()) == 0 {
		shortUsage()
		os.Exit(0)
	}

	debug = debugging(*dbg)
	verbose = debugging(*vb || bool(debug))

	cmd := flag.Arg(0)
	// Commands that don't need the config file to be read or to use
	// the cached OAuth2 token.
	switch cmd {
	case "genkey":
		generateKey()
		return
	case "init":
		createConfigFile(*configFilename)
		return
	case "help":
		usage()
		return
	}

	readConfigFile(*configFilename)

	// Choose the appropriate callback function for the GDrive object to
	// use for debugging output.
	var dpf func(s string, args ...interface{})
	if debug {
		dpf = debugPrint
	} else {
		dpf = debugNoPrint
	}

	var err error
	gd, err = gdrive.New(config.Google.ClientId, config.Google.ClientSecret,
		config.Google.ApiKey, *cachefile, config.Upload.Bytes_per_second_limit,
		config.Download.Bytes_per_second_limit, dpf, *dumpHttp)
	if err != nil {
		printErrorAndExit(fmt.Errorf("error creating Google Drive "+
			"client: %v", err))
	}

	args := flag.Args()[1:]

	errs := 0
	switch cmd {
	case "du":
		errs = du(args)
	case "cat":
		errs = cat(args)
	case "ls":
		errs = ls(args)
	case "mkdir":
		errs = mkdir(args)
	case "upload":
		errs = upload(args)
	case "download":
		errs = download(args)
	case "rm":
		errs = rm(args)
	default:
		shortUsage()
		errs = 1
	}
	os.Exit(errs)
}
