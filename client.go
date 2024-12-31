package oauth2server

import (
	"context"
	"sync"
)

// An OAuth2 Client
type Client interface {
	ID() string

	Secret() string

	// is the oauth2 client "confidential" -- eg can it keep its secret a secret.
	// public clients would be used in places like native apps or single page
	// web apps, while confidential clients are server side.
	IsConfidential() bool

	// Returns the client's allowed redirect URIs
	RedirectURIs() []string
}

// an extension point to let clients to validate their own redirect URIs.
type ClientValidatesRedirectURI interface {
	ValidRedirectURI(ctx context.Context, redirectUri string) bool
}

// an extension point to let clients to validate their own secrets
type ClientValidatesSecrets interface {
	ValidSecret(secret string) bool
}

// extension point to let clients to allowlist grant types
type ClientAllowsGrantType interface {
	AllowsGrantType(grantType string) bool
}

// extension point to allow clients to block response types
type ClientAllowsResponseType interface {
	AllowsResponseType(responseType []string) bool
}

// A storage backend for oauth2 clients.
type ClientRepository interface {
	// Get a single client by its identifier, return a `nil` client if the client
	// with the given identifier is not found. Any errors returned here will
	// be propgaged as server errors.
	Get(ctx context.Context, id string) (Client, error)
}

// fetch a client from the ClientRepository specifically for an authorization request.
// this includes a requirement that clients for auth requests have at least one
// redirect uri registered.
func GetClient(ctx context.Context, clients ClientRepository, clientId string) (Client, *OAuthError) {
	client, err := clients.Get(ctx, clientId)
	if err != nil {
		return nil, MaybeWrapError(err)
	}

	if client == nil {
		return nil, InvalidClientWithCause(ErrClientNotFound, "client %s not found", clientId)
	}

	return client, nil
}

type SimpleClient struct {
	id             string
	secret         string
	redirectUris   []string
	isConfidential bool
}

func NewSimpleClient(id string, secret string, redirectUris []string) Client {
	return &SimpleClient{
		id:             id,
		secret:         secret,
		redirectUris:   redirectUris,
		isConfidential: true,
	}
}

func NewPublicSimpleClient(id string, redirectUris []string) Client {
	return &SimpleClient{
		id:             id,
		redirectUris:   redirectUris,
		isConfidential: false,
	}
}

func (c *SimpleClient) ID() string {
	return c.id
}

func (c *SimpleClient) Secret() string {
	return c.secret
}

func (c *SimpleClient) RedirectURIs() []string {
	return c.redirectUris
}

func (c *SimpleClient) IsConfidential() bool {
	return c.isConfidential
}

type InMemoryClientRepository struct {
	lock    sync.RWMutex
	clients map[string]Client
	errors  map[string]error
}

func NewInMemoryClientRepository() *InMemoryClientRepository {
	return &InMemoryClientRepository{
		clients: make(map[string]Client),
		errors:  make(map[string]error),
	}
}

func (r *InMemoryClientRepository) Get(ctx context.Context, id string) (Client, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	client, _ := r.clients[id]
	err, _ := r.errors[id]

	return client, err
}

func (r *InMemoryClientRepository) Add(c Client) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.clients[c.ID()] = c
}

func (r *InMemoryClientRepository) AddError(id string, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.errors[id] = err
}

func (r *InMemoryClientRepository) Remove(id string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.clients, id)
}

func (r *InMemoryClientRepository) RemoveError(id string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.errors, id)
}
