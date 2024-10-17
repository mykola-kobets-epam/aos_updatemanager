// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2022 Renesas Electronics Corporation.
// Copyright (C) 2022 EPAM Systems, Inc.
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

package iamclient

import (
	"sync"
	"time"

	"github.com/aosedge/aos_common/aoserrors"
	pb "github.com/aosedge/aos_common/api/iamanager"
	"github.com/aosedge/aos_common/utils/cryptutils"
	"github.com/aosedge/aos_common/utils/grpchelpers"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/aosedge/aos_updatemanager/config"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	iamRequestTimeout    = 30 * time.Second
	iamReconnectInterval = 10 * time.Second
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Client IAM client instance.
type Client struct {
	*grpchelpers.IAMPublicServiceClient
	sync.Mutex

	config        *config.Config
	cryptocontext *cryptutils.CryptoContext
	insecure      bool

	connection *grpc.ClientConn

	tlsCertChan      <-chan *pb.CertInfo
	closeChannel     chan struct{}
	disableReconnect bool
	reconnectChannel chan struct{}

	reconnectTimer *time.Timer
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new IAM client.
func New(config *config.Config, cryptocontext *cryptutils.CryptoContext, insecure bool) (client *Client, err error) {
	client = &Client{
		IAMPublicServiceClient: grpchelpers.NewIAMPublicServiceClient(iamRequestTimeout),

		config:        config,
		cryptocontext: cryptocontext,
		insecure:      insecure,

		tlsCertChan:      make(<-chan *pb.CertInfo),
		closeChannel:     make(chan struct{}, 1),
		reconnectChannel: make(chan struct{}, 1),
	}

	defer func() {
		if err != nil {
			client.Close()
		}
	}()

	if err = client.openGRPCConnection(); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if !insecure {
		if ch, err := client.SubscribeCertChanged(config.CertStorage); err != nil {
			return nil, aoserrors.Wrap(err)
		} else {
			client.tlsCertChan = ch
		}
	}

	go client.processEvents()

	return client, nil
}

// Close closes IAM client.
func (client *Client) Close() error {
	client.Lock()
	defer client.Unlock()

	client.disableReconnect = true

	client.closeChannel <- struct{}{}

	if client.reconnectTimer != nil {
		client.reconnectTimer.Stop()
		client.reconnectTimer = nil
	}

	client.closeGRPCConnection()

	log.Debug("Disconnected from IAM")

	return nil
}

// GetNodeID returns node ID.
func (client *Client) GetNodeID() (string, error) {
	response, err := client.GetCurrentNodeInfo()
	if err != nil {
		return "", aoserrors.Wrap(err)
	}

	log.WithFields(log.Fields{"nodeID": response.NodeID, "nodeType": response.NodeType}).Debug("Get node info")

	return response.NodeID, nil
}

func (client *Client) OnConnectionLost() {
	if !client.disableReconnect {
		client.reconnectChannel <- struct{}{}
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (client *Client) openGRPCConnection() (err error) {
	log.Debug("Connecting to IAM...")

	if client.connection, err = grpchelpers.CreatePublicConnection(
		client.config.IAMPublicServerURL, iamRequestTimeout, client.cryptocontext, client.insecure); err != nil {
		return aoserrors.Wrap(err)
	}

	client.RegisterIAMPublicServiceClient(client.connection, client)

	log.Debug("Connected to IAM")

	return nil
}

func (client *Client) closeGRPCConnection() {
	log.Debug("Closing IAM connection...")

	if client.connection != nil {
		client.connection.Close()
		client.connection = nil
	}

	client.WaitIAMPublicServiceClient()
}

func (client *Client) processEvents() {
	for {
		select {
		case <-client.closeChannel:
			return

		case <-client.tlsCertChan:
			client.Lock()
			client.reconnect()
			client.Unlock()

		case <-client.reconnectChannel:
			client.Lock()
			client.reconnect()
			client.Unlock()
		}
	}
}

func (client *Client) reconnect() {
	if client.disableReconnect {
		return
	}

	log.Debug("Reconnecting to IAM server...")

	client.disableReconnect = true
	client.closeGRPCConnection()

	if err := client.openGRPCConnection(); err != nil {
		log.WithField("err", err).Error("Reconnection to IAM failed")

		client.reconnectTimer = time.AfterFunc(iamReconnectInterval, func() {
			client.Lock()
			defer client.Unlock()

			client.reconnectTimer = nil

			client.reconnect()
		})
	} else {
		client.disableReconnect = false
	}
}
