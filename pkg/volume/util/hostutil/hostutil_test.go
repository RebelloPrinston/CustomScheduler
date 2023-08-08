/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hostutil

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/mount-utils"
	"k8s.io/utils/exec"
)

// fakeMounter implements mount.Interface for tests.
type fakeMounter struct {
	mount.FakeMounter
	mountRefs  []string
	raiseError bool
}

// GetMountRefs finds all mount references to the path, returns a
// list of paths.
func (f *fakeMounter) GetMountRefs(pathname string) ([]string, error) {
	if f.raiseError {
		return nil, errors.New("Expected error.")
	}

	return f.mountRefs, nil
}

func TestDeviceNameFromMount(t *testing.T) {
	hu := NewHostUtil()
	path := "/tmp/foo"
	if goruntime.GOOS == "windows" {
		path = "C:" + path
	}

	testCases := map[string]struct {
		mountRefs     []string
		expectedPath  string
		raiseError    bool
		expectedError string
	}{
		"GetMountRefs error": {
			raiseError:    true,
			expectedError: "Expected error.",
		},
		"No Refs error": {
			expectedError: fmt.Sprintf("directory %s is not mounted", path),
		},
		"No Matching refs": {
			mountRefs:    []string{filepath.Join("foo", "lish")},
			expectedPath: filepath.Base(path),
		},
		"Matched ref": {
			mountRefs:    []string{filepath.Join(path, "lish")},
			expectedPath: "lish",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mounter := &fakeMounter{
				mountRefs:  tc.mountRefs,
				raiseError: tc.raiseError,
			}

			path, err := hu.GetDeviceNameFromMount(mounter, path, path)
			if tc.expectedError != "" {
				if err == nil || err.Error() != tc.expectedError {
					t.Fatalf("expected error message `%s` but got `%v`", tc.expectedError, err)
				}
				return
			}

			expectedPath := filepath.FromSlash(tc.expectedPath)
			assert.Equal(t, expectedPath, path)
		})
	}
}

func createSocketFile(socketDir string) (string, error) {
	testSocketFile := filepath.Join(socketDir, "mt.sock")

	// Switch to volume path and create the socket file
	// socket file can not have length of more than 108 character
	// and hence we must use relative path
	oldDir, _ := os.Getwd()

	err := os.Chdir(socketDir)
	if err != nil {
		return "", err
	}
	defer func() {
		os.Chdir(oldDir)
	}()
	_, socketCreateError := net.Listen("unix", "mt.sock")
	return testSocketFile, socketCreateError
}

func TestGetFileType(t *testing.T) {
	// Skip tests that fail on Windows, as discussed during the SIG Testing meeting from January 10, 2023
	if goruntime.GOOS == "windows" {
		t.Skip("Skipping test that fails on Windows")
	}

	hu := NewHostUtil()

	testCase := []struct {
		name         string
		skipWindows  bool
		expectedType FileType
		setUp        func() (string, string, error)
	}{
		{
			"Directory Test",
			false,
			FileTypeDirectory,
			func() (string, string, error) {
				tempDir, err := os.MkdirTemp("", "test-get-filetype-")
				return tempDir, tempDir, err
			},
		},
		{
			"File Test",
			false,
			FileTypeFile,
			func() (string, string, error) {
				tempFile, err := os.CreateTemp("", "test-get-filetype")
				if err != nil {
					return "", "", err
				}
				tempFile.Close()
				return tempFile.Name(), tempFile.Name(), nil
			},
		},
		{
			"Socket Test",
			false,
			FileTypeSocket,
			func() (string, string, error) {
				tempDir, err := os.MkdirTemp("", "test-get-filetype-")
				if err != nil {
					return "", "", err
				}
				tempSocketFile, err := createSocketFile(tempDir)
				return tempSocketFile, tempDir, err
			},
		},
		{
			"Block Device Test",
			true,
			FileTypeBlockDev,
			func() (string, string, error) {
				tempDir, err := os.MkdirTemp("", "test-get-filetype-")
				if err != nil {
					return "", "", err
				}

				tempBlockFile := filepath.Join(tempDir, "test_blk_dev")
				outputBytes, err := exec.New().Command("mknod", tempBlockFile, "b", "89", "1").CombinedOutput()
				if err != nil {
					err = fmt.Errorf("%v: %s ", err, outputBytes)
				}
				return tempBlockFile, tempDir, err
			},
		},
		{
			"Character Device Test",
			true,
			FileTypeCharDev,
			func() (string, string, error) {
				tempDir, err := os.MkdirTemp("", "test-get-filetype-")
				if err != nil {
					return "", "", err
				}

				tempCharFile := filepath.Join(tempDir, "test_char_dev")
				outputBytes, err := exec.New().Command("mknod", tempCharFile, "c", "89", "1").CombinedOutput()
				if err != nil {
					err = fmt.Errorf("%v: %s ", err, outputBytes)
				}
				return tempCharFile, tempDir, err
			},
		},
	}

	for idx, tc := range testCase {
		if goruntime.GOOS == "windows" && tc.skipWindows {
			continue
		}
		path, cleanUpPath, err := tc.setUp()
		defer os.RemoveAll(cleanUpPath) // RemoveAll can deal with a empty path ""
		if err != nil {
			// Locally passed, but upstream CI is not friendly to create such device files
			// Leave "Operation not permitted" out, which can be covered in an e2e test
			if isOperationNotPermittedError(err) {
				continue
			}
			t.Fatalf("[%d-%s] unexpected error : %v", idx, tc.name, err)
		}

		fileType, err := hu.GetFileType(path)
		if err != nil {
			t.Fatalf("[%d-%s] unexpected error : %v", idx, tc.name, err)
		}
		if fileType != tc.expectedType {
			t.Fatalf("[%d-%s] expected %s, but got %s", idx, tc.name, tc.expectedType, fileType)
		}
	}
}

func isOperationNotPermittedError(err error) bool {
	return strings.Contains(err.Error(), "Operation not permitted")
}
