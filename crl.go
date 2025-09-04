package restful

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type clientOrServer interface {
	setCRL(crl map[string]struct{})
	getCRLMu() *sync.RWMutex
}

// set CRL for client or server
func setCRL(ctx context.Context, x clientOrServer, path string, readInterval, fileExistTimeout time.Duration, errChan chan (error)) {
	fileExistDeadline := time.Now().Add(fileExistTimeout)
	// initial read
	crl, err := readCRL(path, x.getCRLMu())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		errChan <- err
	}
	if err == nil {
		x.setCRL(crl)
	}
	go func() {
		ticker := time.NewTicker(readInterval)
		for {
			select {
			case <-ticker.C:
				crl, err = readCRL(path, x.getCRLMu())
				if err != nil {
					// if the file ever existed, we expect it not to be there until the initial timeout
					if errors.Is(err, os.ErrNotExist) && time.Now().Before(fileExistDeadline) {
						continue
					}
					errChan <- err
					continue
				}
				x.setCRL(crl)
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func readCRL(path string, mu *sync.RWMutex) (map[string]struct{}, error) {
	crlBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Handle optional PEM decoding
	if block, _ := pem.Decode(crlBytes); block != nil {
		crlBytes = block.Bytes
	}
	revList, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, err
	}
	if revList.NextUpdate.Before(time.Now()) {
		return nil, fmt.Errorf("revocation list nextupdate is outdated: %s", revList.NextUpdate)
	}

	mu.Lock()
	defer mu.Unlock()

	crl := make(map[string]struct{})
	for _, rc := range revList.RevokedCertificateEntries {
		crl[rc.SerialNumber.String()] = struct{}{}
	}

	return crl, nil
}

func verifyPeerCert(mu *sync.RWMutex, crl *map[string]struct{}) func([][]byte, [][]*x509.Certificate) error {
	// note: pass crl as pointer, and only reassign its value
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			return fmt.Errorf("no verified chains")
		}

		// Parse leaf certificate
		leaf := verifiedChains[0][0]

		mu.RLock()
		defer mu.RUnlock()

		if crl != nil && len(*crl) > 0 {

			// Check revocation
			if _, ok := (*crl)[leaf.SerialNumber.String()]; ok {
				return fmt.Errorf("certificate %X is revoked", leaf.SerialNumber)
			}
		}

		return nil
	}
}
