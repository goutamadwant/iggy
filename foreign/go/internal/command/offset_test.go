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

func TestConsumerOffsetCommandsMarshalBinary(t *testing.T) {
	consumerID, err := iggcon.NewIdentifier(uint32(3))
	if err != nil {
		t.Fatal(err)
	}
	streamID, err := iggcon.NewIdentifier(uint32(1))
	if err != nil {
		t.Fatal(err)
	}
	topicID, err := iggcon.NewIdentifier("t")
	if err != nil {
		t.Fatal(err)
	}
	consumer := iggcon.NewGroupConsumer(consumerID)
	partition := uint32(4)
	prefix := []byte{2, 1, 4, 3, 0, 0, 0, 1, 4, 1, 0, 0, 0, 2, 1, 't'}

	for _, test := range []struct {
		name    string
		command Command
		want    []byte
	}{
		{"StoreWithPartition", &StoreConsumerOffsetRequest{Consumer: consumer, StreamId: streamID, TopicId: topicID, PartitionId: &partition, Offset: 5}, append(append([]byte{}, prefix...), 1, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1)},
		{"StoreWithoutPartition", &StoreConsumerOffsetRequest{Consumer: consumer, StreamId: streamID, TopicId: topicID, Offset: 5}, append(append([]byte{}, prefix...), 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1)},
		{"GetWithPartition", &GetConsumerOffset{Consumer: consumer, StreamId: streamID, TopicId: topicID, PartitionId: &partition}, append(append([]byte{}, prefix...), 1, 4, 0, 0, 0)},
		{"GetWithoutPartition", &GetConsumerOffset{Consumer: consumer, StreamId: streamID, TopicId: topicID}, append(append([]byte{}, prefix...), 0, 0, 0, 0, 0)},
		{"DeleteWithPartition", &DeleteConsumerOffset{Consumer: consumer, StreamId: streamID, TopicId: topicID, PartitionId: &partition}, append(append([]byte{}, prefix...), 1, 4, 0, 0, 0, 1)},
		{"DeleteWithoutPartition", &DeleteConsumerOffset{Consumer: consumer, StreamId: streamID, TopicId: topicID}, append(append([]byte{}, prefix...), 0, 0, 0, 0, 0, 1)},
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
