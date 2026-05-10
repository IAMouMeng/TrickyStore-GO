/*
Author: MouMeng
Mail: iamoumeng@aliyun.com
Date: 2026/4/22 12:12:24
*/

package utils

import (
	"bytes"
	"crypto/rand"
	"os/exec"
	"strings"
)

func Random32Bytes() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	return b
}

func GetProp(key string) (string, error) {
	cmd := exec.Command("getprop", key)

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out.String()), nil
}

func SetProp(key, value string) error {
	cmd := exec.Command("setprop", key, value)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
