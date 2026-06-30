// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package atomsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// requestTimeout bounds a single Atom GraphQL request so a stalled server
// cannot block provisioning indefinitely when the caller's context has no
// deadline of its own.
const requestTimeout = 30 * time.Second

const (
	createEntityMutation = `mutation($tid:ID!,$name:String!){
		createEntity(input:{kind:device,name:$name,tenantId:$tid,attributes:{}}){id}
	}`

	createAPIKeyMutation = `mutation($eid:ID!,$desc:String!){
		createApiKey(entityId:$eid,input:{description:$desc}){credentialId key}
	}`

	createResourceMutation = `mutation($tid:ID!,$name:String!,$oid:ID!){
		createResource(input:{kind:"channel",name:$name,tenantId:$tid,ownerId:$oid,attributes:{}}){id}
	}`

	createPermissionBlockMutation = `mutation($tid:ID!,$cid:ID!,$aid1:ID!,$aid2:ID!){
		createPermissionBlock(input:{
			tenantId:$tid,
			scopeMode:"object",
			objectKind:"resource",
			objectType:"resource:channel",
			objectId:$cid,
			effect:allow,
			actionIds:[$aid1,$aid2]
		}){id}
	}`

	createDirectPolicyMutation = `mutation($tid:ID!,$sid:ID!,$pbid:ID!){
		createDirectPolicy(input:{tenantId:$tid,subjectKind:entity,subjectId:$sid,permissionBlockId:$pbid}){id}
	}`

	deleteEntityMutation = `mutation($id:ID!){
		deleteEntity(id:$id)
	}`

	deleteResourceMutation = `mutation($id:ID!){
		deleteResource(id:$id)
	}`

	revokeCredentialMutation = `mutation($eid:ID!,$cid:ID!){
		revokeCredential(entityId:$eid,credentialId:$cid)
	}`

	deletePermissionBlockMutation = `mutation($id:ID!){
		deletePermissionBlock(id:$id)
	}`

	deleteDirectPolicyMutation = `mutation($id:ID!){
		deleteDirectPolicy(id:$id)
	}`

	actionsQuery = `query{
		actions(limit:100,offset:0){items{id name}}
	}`
)

type Config struct {
	AtomURL string
	Token   string
}

type SDK interface {
	CreateEntity(ctx context.Context, name, tenantID string) (Entity, error)
	CreateAPIKey(ctx context.Context, entityID, description string) (APIKey, error)
	CreateResource(ctx context.Context, name, tenantID, ownerID string) (Resource, error)
	Connect(ctx context.Context, entityID, resourceID, tenantID string) (Grant, error)
	RevokeCredential(ctx context.Context, entityID, credentialID string) error
	DeleteEntity(ctx context.Context, id string) error
	DeleteResource(ctx context.Context, id string) error
	DeletePermissionBlock(ctx context.Context, id string) error
	DeleteDirectPolicy(ctx context.Context, id string) error
}

type Entity struct {
	ID string
}

type Resource struct {
	ID string
}

// APIKey is the result of CreateAPIKey. CredentialID identifies the stored
// credential so it can be revoked (e.g. during provisioning rollback); Key is
// the secret used as the MQTT password.
type APIKey struct {
	Key          string
	CredentialID string
}

// Grant identifies the authorization records Connect creates, so a caller can
// roll them back if a later provisioning step fails.
type Grant struct {
	PermissionBlockID string
	DirectPolicyID    string
}

type graphQLResponse struct {
	Data   map[string]any `json:"data"`
	Errors []any          `json:"errors"`
}

type atomSDK struct {
	cfg    Config
	client *http.Client

	mu        sync.RWMutex
	actionIDs map[string]string
}

func New(cfg Config) SDK {
	return &atomSDK{
		cfg: cfg,
		client: &http.Client{
			Transport: &http.Transport{},
			Timeout:   requestTimeout,
		},
		actionIDs: make(map[string]string),
	}
}

func (s *atomSDK) do(ctx context.Context, query string, vars map[string]any) (map[string]any, error) {
	body := map[string]any{
		"query":     query,
		"variables": vars,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal graphql request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.AtomURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create graphql request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.cfg.Token))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graphql request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read graphql response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graphql request failed with status %d: %s", resp.StatusCode, string(raw))
	}
	var gqlResp graphQLResponse
	if err := json.Unmarshal(raw, &gqlResp); err != nil {
		return nil, fmt.Errorf("unmarshal graphql response: %w", err)
	}
	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("graphql error: %v", gqlResp.Errors)
	}
	return gqlResp.Data, nil
}

func (s *atomSDK) findActionIDs(ctx context.Context, names ...string) (map[string]string, error) {
	s.mu.RLock()
	missing := make([]string, 0, len(names))
	for _, n := range names {
		if _, ok := s.actionIDs[n]; !ok {
			missing = append(missing, n)
		}
	}
	s.mu.RUnlock()

	if len(missing) > 0 {
		data, err := s.do(ctx, actionsQuery, nil)
		if err != nil {
			return nil, fmt.Errorf("query actions: %w", err)
		}
		actionsData, ok := data["actions"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("actions: unexpected response shape")
		}
		items, ok := actionsData["items"].([]any)
		if !ok {
			return nil, fmt.Errorf("actions.items: unexpected shape")
		}
		s.mu.Lock()
		for _, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			id, _ := entry["id"].(string)
			name, _ := entry["name"].(string)
			if id != "" && name != "" {
				s.actionIDs[name] = id
			}
		}
		s.mu.Unlock()
	}

	// Return a copy of the requested IDs so callers never read the shared
	// cache concurrently with a writer.
	result := make(map[string]string, len(names))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range names {
		id, ok := s.actionIDs[n]
		if !ok {
			return nil, fmt.Errorf("action %q not found on server", n)
		}
		result[n] = id
	}
	return result, nil
}

func (s *atomSDK) CreateEntity(ctx context.Context, name, tenantID string) (Entity, error) {
	data, err := s.do(ctx, createEntityMutation, map[string]any{
		"tid":  tenantID,
		"name": name,
	})
	if err != nil {
		return Entity{}, err
	}
	ent, ok := data["createEntity"].(map[string]any)
	if !ok {
		return Entity{}, fmt.Errorf("createEntity: unexpected response shape")
	}
	id, _ := ent["id"].(string)
	if id == "" {
		return Entity{}, fmt.Errorf("createEntity: empty id in response")
	}
	return Entity{ID: id}, nil
}

func (s *atomSDK) CreateAPIKey(ctx context.Context, entityID, description string) (APIKey, error) {
	data, err := s.do(ctx, createAPIKeyMutation, map[string]any{
		"eid":  entityID,
		"desc": description,
	})
	if err != nil {
		return APIKey{}, err
	}
	keyData, ok := data["createApiKey"].(map[string]any)
	if !ok {
		return APIKey{}, fmt.Errorf("createApiKey: unexpected response shape")
	}
	key, _ := keyData["key"].(string)
	if key == "" {
		return APIKey{}, fmt.Errorf("createApiKey: empty key in response")
	}
	credentialID, _ := keyData["credentialId"].(string)
	return APIKey{Key: key, CredentialID: credentialID}, nil
}

func (s *atomSDK) CreateResource(ctx context.Context, name, tenantID, ownerID string) (Resource, error) {
	data, err := s.do(ctx, createResourceMutation, map[string]any{
		"tid":  tenantID,
		"oid":  ownerID,
		"name": name,
	})
	if err != nil {
		return Resource{}, err
	}
	res, ok := data["createResource"].(map[string]any)
	if !ok {
		return Resource{}, fmt.Errorf("createResource: unexpected response shape")
	}
	id, _ := res["id"].(string)
	if id == "" {
		return Resource{}, fmt.Errorf("createResource: empty id in response")
	}
	return Resource{ID: id}, nil
}

func (s *atomSDK) Connect(ctx context.Context, entityID, resourceID, tenantID string) (Grant, error) {
	actionIDs, err := s.findActionIDs(ctx, "publish", "subscribe")
	if err != nil {
		return Grant{}, fmt.Errorf("lookup action ids: %w", err)
	}

	pbData, err := s.do(ctx, createPermissionBlockMutation, map[string]any{
		"tid":  tenantID,
		"cid":  resourceID,
		"aid1": actionIDs["publish"],
		"aid2": actionIDs["subscribe"],
	})
	if err != nil {
		return Grant{}, fmt.Errorf("create permission block: %w", err)
	}
	pb, ok := pbData["createPermissionBlock"].(map[string]any)
	if !ok {
		return Grant{}, fmt.Errorf("createPermissionBlock: unexpected response shape")
	}
	pbID, _ := pb["id"].(string)
	if pbID == "" {
		return Grant{}, fmt.Errorf("createPermissionBlock: empty id in response")
	}
	dpData, err := s.do(ctx, createDirectPolicyMutation, map[string]any{
		"tid":  tenantID,
		"sid":  entityID,
		"pbid": pbID,
	})
	if err != nil {
		// The permission block was created but the policy that uses it was
		// not, so clean it up rather than leaking an orphaned record.
		_ = s.DeletePermissionBlock(context.WithoutCancel(ctx), pbID)
		return Grant{}, fmt.Errorf("create direct policy: %w", err)
	}
	dp, ok := dpData["createDirectPolicy"].(map[string]any)
	if !ok {
		return Grant{}, fmt.Errorf("createDirectPolicy: unexpected response shape")
	}
	dpID, _ := dp["id"].(string)
	return Grant{PermissionBlockID: pbID, DirectPolicyID: dpID}, nil
}

func (s *atomSDK) RevokeCredential(ctx context.Context, entityID, credentialID string) error {
	_, err := s.do(ctx, revokeCredentialMutation, map[string]any{
		"eid": entityID,
		"cid": credentialID,
	})
	return err
}

func (s *atomSDK) DeletePermissionBlock(ctx context.Context, id string) error {
	_, err := s.do(ctx, deletePermissionBlockMutation, map[string]any{
		"id": id,
	})
	return err
}

func (s *atomSDK) DeleteDirectPolicy(ctx context.Context, id string) error {
	_, err := s.do(ctx, deleteDirectPolicyMutation, map[string]any{
		"id": id,
	})
	return err
}

func (s *atomSDK) DeleteEntity(ctx context.Context, id string) error {
	_, err := s.do(ctx, deleteEntityMutation, map[string]any{
		"id": id,
	})
	return err
}

func (s *atomSDK) DeleteResource(ctx context.Context, id string) error {
	_, err := s.do(ctx, deleteResourceMutation, map[string]any{
		"id": id,
	})
	return err
}
