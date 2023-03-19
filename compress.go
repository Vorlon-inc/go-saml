package saml

import (
	"bytes"
	"compress/flate"
	"io"
	"strings"
)

func compressString(in string) (string, error) {
	buf := new(bytes.Buffer)
	compressor, err := flate.NewWriter(buf, 9)
	if err != nil {
		return "", err
	}
	_, err = compressor.Write([]byte(in))
	if err != nil {
		return "", err
	}
	err = compressor.Close()
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func decompressString(in string) (string, error) {
	buf := new(bytes.Buffer)
	decompressor := flate.NewReader(strings.NewReader(in))
	_, err := io.Copy(buf, decompressor)
	if err != nil {
		return "", err
	}
	err = decompressor.Close()
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func compress(in []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	compressor, err := flate.NewWriter(buf, 9)
	if err != nil {
		return nil, err
	}
	_, err = compressor.Write(in)
	if err != nil {
		return nil, err
	}
	err = compressor.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(in []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	decompressor := flate.NewReader(bytes.NewReader(in))
	_, err := io.Copy(buf, decompressor)
	if err != nil {
		return nil, err
	}
	err = decompressor.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
