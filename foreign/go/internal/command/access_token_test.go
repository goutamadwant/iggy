// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package command

import (
	"bytes"
	"testing"
)

func TestPersonalAccessTokenCommandsMarshalBinary(t *testing.T) {
	for _, test := range []struct {
		name    string
		command Command
		want    []byte
	}{
		{"CreatePersonalAccessToken", &CreatePersonalAccessToken{Name: "token", Expiry: 0x01020304}, []byte{5, 't', 'o', 'k', 'e', 'n', 4, 3, 2, 1, 0, 0, 0, 0}},
		{"DeletePersonalAccessToken", &DeletePersonalAccessToken{Name: "token"}, []byte{5, 't', 'o', 'k', 'e', 'n'}},
		{"GetPersonalAccessTokens", &GetPersonalAccessTokens{}, []byte{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.command.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("body = %v, want %v", got, test.want)
			}
		})
	}
}
