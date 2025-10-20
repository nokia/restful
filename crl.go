package restful

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type crl struct {
	mu          sync.RWMutex
	serials     map[string]struct{}
	nextUpdate  time.Time
	strictCheck bool
}

type clientOrServer interface {
	setCRL(serials map[string]struct{}, nextUpdate time.Time, strict bool)
	getCRL() *crl
}

var (
	// ErrRevocationListReadError is when error happen during reading of revocation list
	ErrRevocationListReadError = errors.New("error reading revocation list")
	// ErrRevocationListOutOfDate is when the revocation list is out of date
	ErrRevocationListOutOfDate = errors.New("revocation list out of date")
	// ErrCertificateRevoked happens when the certificate revoked
	ErrCertificateRevoked = errors.New("certificate revoked")
)

// CRLOptions defines the settings restful clients/servers can use for CRL verification
type CRLOptions struct {
	// Ctx is a cancelable background context used for the regular CRL reading
	Ctx context.Context

	// CRLLocation is the file name or comma-separated HTTP distribution point URI list where the revocation list shall be from
	CRLLocation string

	// ReadInterval is the time interval the CRL information is retrieved from the distribution list or re-read from the file
	ReadInterval time.Duration

	// FileExistTimeout allows for the CRL file to not exist for an initial duration of time without reporting an error
	FileExistTimeout time.Duration

	// StatusChan is a channel where the CRL status can be provided.
	// Every ReadInterval, an error is sent on the channel if getting the CRL is not successful or if the NextUpdate in the
	// latest CRL is in the past, or nil is sent in case of no error.
	StatusChan chan (error)

	// StrictValityCheck enables strict NextUpdate checking.
	// With this enabled, peer certificate checks will fail if the latest CRL file is outdated
	StrictValityCheck bool
}

// set CRL for client or server.
// runs a periodic loop to re-read CRL
func setCRL(x clientOrServer, o CRLOptions) {
	if o.Ctx == nil {
		o.Ctx = context.Background()
	}
	fileExistDeadline := time.Now().Add(o.FileExistTimeout)
	// initial read
	crl, nextUpdate, lastModification, err := readCRL(o.CRLLocation, fileExistDeadline, time.Time{}, time.Time{})

	if err == nil {
		x.setCRL(crl, nextUpdate, o.StrictValityCheck)
	} else {
		// always initialize CRL pointer
		x.setCRL(nil, time.Time{}, o.StrictValityCheck)
		if o.StatusChan != nil {
			o.StatusChan <- err
		}
	}

	go func() {
		ticker := time.NewTicker(o.ReadInterval)
		for {
			select {
			case <-ticker.C:
				crl, nextUpdate, lastModification, err = readCRL(o.CRLLocation, fileExistDeadline, nextUpdate, lastModification)
				if err == nil && !lastModification.IsZero() {
					x.setCRL(crl, nextUpdate, o.StrictValityCheck)
				}
				if o.StatusChan != nil {
					o.StatusChan <- err
				}

			case <-o.Ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// readCRL reads the list of expired certificates from a location (file name or URL).
// It can send an error or nil the provided status channel when the status potentially changes.
// Will not send error if the file at the provided path doesn't exist before the provided deadline.
// If CRLLocation is a file, it is not re-read until it's last modification date is after lastKnownFileDate.
func readCRL(location string, deadline, nextUpdate, lastModified time.Time) (map[string]struct{}, time.Time, time.Time, error) {
	crlBytes, newLastModified, err := getCRLBody(location, lastModified)
	if err != nil {
		if time.Now().Before(deadline) && errors.Is(err, os.ErrNotExist) {
			return nil, time.Time{}, time.Time{}, nil
		}
		return nil, time.Time{}, time.Time{}, err
	}
	if crlBytes == nil {
		// the file date has not changed since last read.
		// may be past nextUpdate
		err := checkNextUpdate(nextUpdate)
		return nil, time.Time{}, time.Time{}, err
	}

	// Handle optional PEM decoding
	if block, _ := pem.Decode(crlBytes); block != nil {
		crlBytes = block.Bytes
	}
	revList, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		err = fmt.Errorf("%w: %s", ErrRevocationListReadError, err)
		return nil, time.Time{}, newLastModified, err
	}
	nextUpdate = revList.NextUpdate

	crl := make(map[string]struct{})
	for _, rc := range revList.RevokedCertificateEntries {
		crl[rc.SerialNumber.String()] = struct{}{}
	}

	err = checkNextUpdate(nextUpdate)
	if err != nil {
		return crl, nextUpdate, newLastModified, err
	}

	return crl, nextUpdate, newLastModified, nil
}

func checkNextUpdate(nextUpdate time.Time) error {
	if nextUpdate.Before(time.Now()) {
		return fmt.Errorf("%w: revocation list nextupdate is outdated: %s", ErrRevocationListOutOfDate, nextUpdate)
	}
	return nil
}

// getCRLbody returns the body and last modification time of the new CRL file,
// or nothing, if the file has not been modified since the given timestamp.
// If location is an URL, it will return the current time.
func getCRLBody(location string, lastModified time.Time) ([]byte, time.Time, error) {
	var crlBytes []byte
	var err error
	if strings.HasPrefix(location, "http://") {
		crlURIs := strings.Split(location, ",")
		var resp *http.Response

		for _, uri := range crlURIs {
			uri = strings.Trim(uri, " ")
			resp, err = http.Get(uri) // #nosec G107 - HTTP request made with variable uri
			if err != nil {
				continue
			}
		}
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("%w: couldn't download CRL: %s", ErrRevocationListReadError, err)
		}
		crlBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("%w: couldn't read CRL body: %s", ErrRevocationListReadError, err)
		}
		return crlBytes, time.Now(), nil
	}
	info, err := os.Stat(location)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: couldn't read CRL file: %s", ErrRevocationListReadError, err)
	}
	if !info.ModTime().After(lastModified) {
		return nil, time.Time{}, nil
	}
	crlBytes, err = os.ReadFile(location) // #nosec G304 - file path is provided in variable
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: couldn't read CRL file: %s", ErrRevocationListReadError, err)
	}

	return crlBytes, info.ModTime(), nil
}

func verifyPeerCert(crl *crl) func([][]byte, [][]*x509.Certificate) error {
	// note: pass crl as pointer, and only reassign its value
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			return fmt.Errorf("no verified chains")
		}
		if crl == nil {
			return nil
		}
		if crl.strictCheck && crl.nextUpdate.Before(time.Now()) {
			return ErrRevocationListOutOfDate
		}

		// Parse leaf certificate
		leaf := verifiedChains[0][0]

		crl.mu.RLock()
		defer crl.mu.RUnlock()

		if len(crl.serials) > 0 {

			// Check revocation
			if _, ok := crl.serials[leaf.SerialNumber.String()]; ok {
				return fmt.Errorf("%w: %X", ErrCertificateRevoked, leaf.SerialNumber)
			}
		}

		return nil
	}
}
