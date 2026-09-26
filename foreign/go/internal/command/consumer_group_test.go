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

	iggcon "github.com/apache/iggy/foreign/go/contracts"
)

func TestConsumerGroupCommandsMarshalBinary(t *testing.T) {
	streamID, err := iggcon.NewIdentifier(uint32(1))
	if err != nil {
		t.Fatal(err)
	}
	topicID, err := iggcon.NewIdentifier("t")
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := iggcon.NewIdentifier(uint32(3))
	if err != nil {
		t.Fatal(err)
	}
	path := TopicPath{StreamId: streamID, TopicId: topicID}
	prefix := []byte{1, 4, 1, 0, 0, 0, 2, 1, 't'}
	withGroup := []byte{1, 4, 1, 0, 0, 0, 2, 1, 't', 1, 4, 3, 0, 0, 0}

	for _, test := range []struct {
		name    string
		command Command
		want    []byte
	}{
		{"CreateConsumerGroup", &CreateConsumerGroup{TopicPath: path, Name: "g"}, []byte{1, 4, 1, 0, 0, 0, 2, 1, 't', 1, 'g'}},
		{"GetConsumerGroup", &GetConsumerGroup{TopicPath: path, GroupId: groupID}, withGroup},
		{"GetConsumerGroups", &GetConsumerGroups{StreamId: streamID, TopicId: topicID}, prefix},
		{"JoinConsumerGroup", &JoinConsumerGroup{TopicPath: path, GroupId: groupID}, withGroup},
		{"LeaveConsumerGroup", &LeaveConsumerGroup{TopicPath: path, GroupId: groupID}, withGroup},
		{"SyncConsumerGroup", &SyncConsumerGroup{TopicPath: path, GroupId: groupID}, withGroup},
		{"DeleteConsumerGroup", &DeleteConsumerGroup{TopicPath: path, GroupId: groupID}, withGroup},
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
