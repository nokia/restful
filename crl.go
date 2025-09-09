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

	// ErrChan is a channel where error reports are sent (if not nil)
	ErrChan chan (error)

	// StrictValityCheck enables strict NextUpdate checking.
	// With this enabled, peer certificate checks will fail if the latest CRL file is outdated
	StrictValityCheck bool
}

// set CRL for client or server
func setCRL(x clientOrServer, o CRLOptions) {
	fileExistDeadline := time.Now().Add(o.FileExistTimeout)
	// initial read
	crl, nextUpdate, err := readCRL(o.CRLLocation)
	if err != nil && !errors.Is(err, os.ErrNotExist) && o.ErrChan != nil {
		o.ErrChan <- err
	}
	if err == nil {
		x.setCRL(crl, nextUpdate, o.StrictValityCheck)
	}
	go func() {
		ticker := time.NewTicker(o.ReadInterval)
		for {
			select {
			case <-ticker.C:
				crl, nextUpdate, err = readCRL(o.CRLLocation)
				if err != nil {
					// if the file ever existed, we expect it not to be there until the initial timeout
					if errors.Is(err, os.ErrNotExist) && time.Now().Before(fileExistDeadline) {
						continue
					}
					if o.ErrChan != nil {
						o.ErrChan <- err
					}
					continue
				}
				x.setCRL(crl, nextUpdate, o.StrictValityCheck)
			case <-o.Ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func readCRL(location string) (map[string]struct{}, time.Time, error) {

	crlBytes, err := getCRLBody(location)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Handle optional PEM decoding
	if block, _ := pem.Decode(crlBytes); block != nil {
		crlBytes = block.Bytes
	}
	revList, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, time.Time{}, err
	}
	nextUpdate := revList.NextUpdate
	if nextUpdate.Before(time.Now()) {
		return nil, time.Time{}, fmt.Errorf("revocation list nextupdate is outdated: %s", revList.NextUpdate)
	}

	crl := make(map[string]struct{})
	for _, rc := range revList.RevokedCertificateEntries {
		crl[rc.SerialNumber.String()] = struct{}{}
	}

	return crl, nextUpdate, nil
}

func getCRLBody(location string) ([]byte, error) {
	var crlBytes []byte
	var err error
	if strings.HasPrefix(location, "http://") {
		crlURIs := strings.Split(location, ",")
		var resp *http.Response

		for _, uri := range crlURIs {
			uri = strings.Trim(uri, " ")
			resp, err = http.Get(uri)
			if err != nil {
				continue
			}
		}
		if err != nil {
			return nil, fmt.Errorf("couldn't download CRL: %s", err)
		}
		crlBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading CRL body: %s", err)
		}
		return crlBytes, nil
	}
	crlBytes, err = os.ReadFile(location)
	if err != nil {
		return nil, err
	}
	return crlBytes, nil
}

func verifyPeerCert(crl *crl) func([][]byte, [][]*x509.Certificate) error {
	// note: pass crl as pointer, and only reassign its value
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			return fmt.Errorf("no verified chains")
		}

		if crl.strictCheck && crl.nextUpdate.Before(time.Now()) {
			return fmt.Errorf("revocation list's NextUpdate is in the past")
		}

		// Parse leaf certificate
		leaf := verifiedChains[0][0]

		crl.mu.RLock()
		defer crl.mu.RUnlock()

		if len(crl.serials) > 0 {

			// Check revocation
			if _, ok := crl.serials[leaf.SerialNumber.String()]; ok {
				return fmt.Errorf("certificate %X is revoked", leaf.SerialNumber)
			}
		}

		return nil
	}
}
