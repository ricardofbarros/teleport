/*
Copyright 2016-2020 Gravitational, Inc.

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

package types

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/utils"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gravitational/trace"
	"github.com/pborman/uuid"
	"github.com/tstranex/u2f"
)

// AuthPreference defines the authentication preferences for a specific
// cluster. It defines the type (local, oidc) and second factor (off, otp, oidc).
// AuthPreference is a configuration resource, never create more than one instance
// of it.
type AuthPreference interface {
	// Resource provides common resource properties.
	Resource

	// GetType gets the type of authentication: local, saml, or oidc.
	GetType() string
	// SetType sets the type of authentication: local, saml, or oidc.
	SetType(string)

	// GetSecondFactor gets the type of second factor: off, otp or u2f.
	GetSecondFactor() string
	// SetSecondFactor sets the type of second factor: off, otp, or u2f.
	SetSecondFactor(string)

	// GetConnectorName gets the name of the OIDC or SAML connector to use. If
	// this value is empty, we fall back to the first connector in the backend.
	GetConnectorName() string
	// SetConnectorName sets the name of the OIDC or SAML connector to use. If
	// this value is empty, we fall back to the first connector in the backend.
	SetConnectorName(string)

	// GetU2F gets the U2F configuration settings.
	GetU2F() (*U2F, error)
	// SetU2F sets the U2F configuration settings.
	SetU2F(*U2F)

	// CheckAndSetDefaults sets and default values and then
	// verifies the constraints for AuthPreference.
	CheckAndSetDefaults() error

	// String represents a human readable version of authentication settings.
	String() string
}

// NewAuthPreference is a convenience method to to create AuthPreferenceV2.
func NewAuthPreference(spec AuthPreferenceSpecV2) (AuthPreference, error) {
	pref := AuthPreferenceV2{
		Kind:    KindClusterAuthPreference,
		Version: V2,
		Metadata: Metadata{
			Name:      MetaNameClusterAuthPreference,
			Namespace: defaults.Namespace,
		},
		Spec: spec,
	}

	if err := pref.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &pref, nil
}

// DefaultAuthPreference returns the default authentication preferences.
func DefaultAuthPreference() AuthPreference {
	return &AuthPreferenceV2{
		Kind:    KindClusterAuthPreference,
		Version: V2,
		Metadata: Metadata{
			Name:      MetaNameClusterAuthPreference,
			Namespace: defaults.Namespace,
		},
		Spec: AuthPreferenceSpecV2{
			Type:         constants.Local,
			SecondFactor: constants.OTP,
		},
	}
}

// AuthPreferenceV2 implements AuthPreference.
type AuthPreferenceV2 struct {
	// Kind is a resource kind - always resource.
	Kind string `json:"kind"`

	// SubKind is a resource sub kind.
	SubKind string `json:"sub_kind,omitempty"`

	// Version is a resource version.
	Version string `json:"version"`

	// Metadata is metadata about the resource.
	Metadata Metadata `json:"metadata"`

	// Spec is the specification of the resource.
	Spec AuthPreferenceSpecV2 `json:"spec"`
}

// GetVersion returns resource version.
func (c *AuthPreferenceV2) GetVersion() string {
	return c.Version
}

// GetName returns the name of the resource.
func (c *AuthPreferenceV2) GetName() string {
	return c.Metadata.Name
}

// SetName sets the name of the resource.
func (c *AuthPreferenceV2) SetName(e string) {
	c.Metadata.Name = e
}

// SetExpiry sets expiry time for the object.
func (c *AuthPreferenceV2) SetExpiry(expires time.Time) {
	c.Metadata.SetExpiry(expires)
}

// Expiry returns object expiry setting.
func (c *AuthPreferenceV2) Expiry() time.Time {
	return c.Metadata.Expiry()
}

// SetTTL sets Expires header using the provided clock.
// Use SetExpiry instead.
// DELETE IN 7.0.0
func (c *AuthPreferenceV2) SetTTL(clock Clock, ttl time.Duration) {
	c.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns object metadata.
func (c *AuthPreferenceV2) GetMetadata() Metadata {
	return c.Metadata
}

// GetResourceID returns resource ID.
func (c *AuthPreferenceV2) GetResourceID() int64 {
	return c.Metadata.ID
}

// SetResourceID sets resource ID.
func (c *AuthPreferenceV2) SetResourceID(id int64) {
	c.Metadata.ID = id
}

// GetKind returns resource kind.
func (c *AuthPreferenceV2) GetKind() string {
	return c.Kind
}

// GetSubKind returns resource subkind.
func (c *AuthPreferenceV2) GetSubKind() string {
	return c.SubKind
}

// SetSubKind sets resource subkind.
func (c *AuthPreferenceV2) SetSubKind(sk string) {
	c.SubKind = sk
}

// GetType returns the type of authentication.
func (c *AuthPreferenceV2) GetType() string {
	return c.Spec.Type
}

// SetType sets the type of authentication.
func (c *AuthPreferenceV2) SetType(s string) {
	c.Spec.Type = s
}

// GetSecondFactor returns the type of second factor.
func (c *AuthPreferenceV2) GetSecondFactor() string {
	return c.Spec.SecondFactor
}

// SetSecondFactor sets the type of second factor.
func (c *AuthPreferenceV2) SetSecondFactor(s string) {
	c.Spec.SecondFactor = s
}

// GetConnectorName gets the name of the OIDC or SAML connector to use. If
// this value is empty, we fall back to the first connector in the backend.
func (c *AuthPreferenceV2) GetConnectorName() string {
	return c.Spec.ConnectorName
}

// SetConnectorName sets the name of the OIDC or SAML connector to use. If
// this value is empty, we fall back to the first connector in the backend.
func (c *AuthPreferenceV2) SetConnectorName(cn string) {
	c.Spec.ConnectorName = cn
}

// GetU2F gets the U2F configuration settings.
func (c *AuthPreferenceV2) GetU2F() (*U2F, error) {
	if c.Spec.U2F == nil {
		return nil, trace.NotFound("U2F configuration not found")
	}
	return c.Spec.U2F, nil
}

// SetU2F sets the U2F configuration settings.
func (c *AuthPreferenceV2) SetU2F(u2f *U2F) {
	c.Spec.U2F = u2f
}

// CheckAndSetDefaults verifies the constraints for AuthPreference.
func (c *AuthPreferenceV2) CheckAndSetDefaults() error {
	// make sure we have defaults for all metadata fields
	err := c.Metadata.CheckAndSetDefaults()
	if err != nil {
		return trace.Wrap(err)
	}

	// if nothing is passed in, set defaults
	if c.Spec.Type == "" {
		c.Spec.Type = constants.Local
	}
	if c.Spec.SecondFactor == "" {
		c.Spec.SecondFactor = constants.OTP
	}

	// make sure type makes sense
	switch c.Spec.Type {
	case constants.Local, constants.OIDC, constants.SAML, constants.Github:
	default:
		return trace.BadParameter("authentication type %q not supported", c.Spec.Type)
	}

	// make sure second factor makes sense
	switch c.Spec.SecondFactor {
	case constants.OFF, constants.OTP, constants.U2F:
	default:
		return trace.BadParameter("second factor type %q not supported", c.Spec.SecondFactor)
	}

	return nil
}

// String represents a human readable version of authentication settings.
func (c *AuthPreferenceV2) String() string {
	return fmt.Sprintf("AuthPreference(Type=%q,SecondFactor=%q)", c.Spec.Type, c.Spec.SecondFactor)
}

// AuthPreferenceSpecV2 is the actual data we care about for AuthPreferenceV2.
type AuthPreferenceSpecV2 struct {
	// Type is the type of authentication.
	Type string `json:"type"`

	// SecondFactor is the type of second factor.
	SecondFactor string `json:"second_factor,omitempty"`

	// ConnectorName is the name of the OIDC or SAML connector. If this value is
	// not set the first connector in the backend will be used.
	ConnectorName string `json:"connector_name,omitempty"`

	// U2F are the settings for the U2F device.
	U2F *U2F `json:"u2f,omitempty"`
}

// U2F defines settings for U2F device.
type U2F struct {
	// AppID returns the application ID for universal second factor.
	AppID string `json:"app_id,omitempty"`

	// Facets returns the facets for universal second factor.
	Facets []string `json:"facets,omitempty"`
}

// Check validates local auth secret members.
func (l *LocalAuthSecrets) Check() error {
	if len(l.PasswordHash) > 0 {
		if _, err := bcrypt.Cost(l.PasswordHash); err != nil {
			return trace.BadParameter("invalid password hash")
		}
	}
	mfaNames := make(map[string]struct{}, len(l.MFA))
	for _, d := range l.MFA {
		if err := d.CheckAndSetDefaults(); err != nil {
			return trace.BadParameter("MFA device named %q is invalid: %v", d.Metadata.Name, err)
		}
		if _, ok := mfaNames[d.Metadata.Name]; ok {
			return trace.BadParameter("MFA device named %q already exists", d.Metadata.Name)
		}
		mfaNames[d.Metadata.Name] = struct{}{}
	}
	return nil
}

// Equals checks equality (nil safe).
func (l *LocalAuthSecrets) Equals(other *LocalAuthSecrets) bool {
	if (l == nil) || (other == nil) {
		return l == other
	}
	if !bytes.Equal(l.PasswordHash, other.PasswordHash) {
		return false
	}
	if len(l.MFA) != len(other.MFA) {
		return false
	}
	mfa := make(map[string]*MFADevice, len(l.MFA))
	for i, d := range l.MFA {
		mfa[d.Id] = l.MFA[i]
	}
	mfaOther := make(map[string]*MFADevice, len(other.MFA))
	for i, d := range other.MFA {
		mfaOther[d.Id] = other.MFA[i]
	}
	for id, d := range mfa {
		od, ok := mfaOther[id]
		if !ok {
			return false
		}
		if !d.Equals(od) {
			return false
		}
	}
	return true
}

// newMFADevice creates a new MFADevice with the given name. Caller must set
// the Device field in the returned MFADevice.
func newMFADevice(name string, addedAt time.Time) *MFADevice {
	return &MFADevice{
		Kind: KindMFADevice,
		Metadata: Metadata{
			Name: name,
		},
		Id:       uuid.New(),
		AddedAt:  addedAt,
		LastUsed: addedAt,
	}
}

func (d *MFADevice) CheckAndSetDefaults() error {
	if err := d.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if d.Kind == "" {
		return trace.BadParameter("MFADevice missing Kind field")
	}
	if d.Version == "" {
		d.Version = V1
	}
	if d.Id == "" {
		return trace.BadParameter("MFADevice missing ID field")
	}
	if d.AddedAt.IsZero() {
		return trace.BadParameter("MFADevice missing AddedAt field")
	}
	if d.LastUsed.IsZero() {
		return trace.BadParameter("MFADevice missing LastUsed field")
	}
	if d.LastUsed.Before(d.AddedAt) {
		return trace.BadParameter("MFADevice LastUsed field must be earlier than AddedAt")
	}
	if d.Device == nil {
		return trace.BadParameter("MFADevice missing Device field")
	}
	switch dd := d.Device.(type) {
	case *MFADevice_Totp:
		if err := dd.Totp.Check(); err != nil {
			return trace.Wrap(err)
		}
	case *MFADevice_U2F:
		if err := dd.U2F.Check(); err != nil {
			return trace.Wrap(err)
		}
	default:
		return trace.BadParameter("MFADevice has Device field of unknown type %T", d.Device)
	}
	return nil
}

func (d *MFADevice) Equals(other *MFADevice) bool {
	if (d == nil) || (other == nil) {
		return d == other
	}
	if d.Kind != other.Kind {
		return false
	}
	if d.SubKind != other.SubKind {
		return false
	}
	if d.Version != other.Version {
		return false
	}
	if d.Metadata.Name != other.Metadata.Name {
		return false
	}
	if d.Id != other.Id {
		return false
	}
	if !d.AddedAt.Equal(other.AddedAt) {
		return false
	}
	// Ignore LastUsed, it's a very dynamic field.
	if !d.GetTotp().Equals(other.GetTotp()) {
		return false
	}
	if !d.GetU2F().Equals(other.GetU2F()) {
		return false
	}
	return true
}

func (d *MFADevice) GetKind() string                       { return d.Kind }
func (d *MFADevice) GetSubKind() string                    { return d.SubKind }
func (d *MFADevice) SetSubKind(sk string)                  { d.SubKind = sk }
func (d *MFADevice) GetVersion() string                    { return d.Version }
func (d *MFADevice) GetMetadata() Metadata                 { return d.Metadata }
func (d *MFADevice) GetName() string                       { return d.Metadata.GetName() }
func (d *MFADevice) SetName(n string)                      { d.Metadata.SetName(n) }
func (d *MFADevice) GetResourceID() int64                  { return d.Metadata.ID }
func (d *MFADevice) SetResourceID(id int64)                { d.Metadata.SetID(id) }
func (d *MFADevice) Expiry() time.Time                     { return d.Metadata.Expiry() }
func (d *MFADevice) SetExpiry(exp time.Time)               { d.Metadata.SetExpiry(exp) }
func (d *MFADevice) SetTTL(clock Clock, ttl time.Duration) { d.Metadata.SetTTL(clock, ttl) }

func (d *MFADevice) MarshalJSON() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := (&jsonpb.Marshaler{}).Marshal(buf, d)
	return buf.Bytes(), trace.Wrap(err)
}

func (d *MFADevice) UnmarshalJSON(buf []byte) error {
	return jsonpb.Unmarshal(bytes.NewReader(buf), d)
}

// NewTOTPDevice creates a TOTP MFADevice from the given key.
func NewTOTPDevice(name, key string, addedAt time.Time) (*MFADevice, error) {
	d := newMFADevice(name, addedAt)
	d.Device = &MFADevice_Totp{Totp: &TOTPDevice{
		Key: key,
	}}
	if err := d.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return d, nil
}

func (d *TOTPDevice) Check() error {
	if d.Key == "" {
		return trace.BadParameter("TOTPDevice missing Key field")
	}
	return nil
}

func (d *TOTPDevice) Equals(other *TOTPDevice) bool {
	if (d == nil) || (other == nil) {
		return d == other
	}
	return d.Key == other.Key
}

// NewU2FDevice creates a U2F MFADevice object from a completed U2F
// registration.
func NewU2FDevice(name string, reg *u2f.Registration, addedAt time.Time) (*MFADevice, error) {
	d := newMFADevice(name, addedAt)
	pubKey, err := x509.MarshalPKIXPublicKey(&reg.PubKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	d.Device = &MFADevice_U2F{U2F: &U2FDevice{
		KeyHandle: reg.KeyHandle,
		PubKey:    pubKey,
	}}
	if err := d.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return d, nil
}

func (d *U2FDevice) Check() error {
	if len(d.KeyHandle) == 0 {
		return trace.BadParameter("U2FDevice missing KeyHandle field")
	}
	if len(d.PubKey) == 0 {
		return trace.BadParameter("U2FDevice missing PubKey field")
	}
	if _, err := d.GetPubKeyDecoded(); err != nil {
		return trace.BadParameter("U2FDevice PubKey is invalid: %v", err)
	}
	return nil
}

// GetPubKeyDecoded returns the ECDSA public key of this U2F device
// registration.
func (d *U2FDevice) GetPubKeyDecoded() (*ecdsa.PublicKey, error) {
	pubKeyI, err := x509.ParsePKIXPublicKey(d.PubKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	pubKey, ok := pubKeyI.(*ecdsa.PublicKey)
	if !ok {
		return nil, trace.BadParameter("expected *ecdsa.PublicKey, got %T", pubKeyI)
	}
	return pubKey, nil
}

// Equals checks equality (nil safe).
func (d *U2FDevice) Equals(other *U2FDevice) bool {
	if (d == nil) || (other == nil) {
		return d == other
	}
	if !bytes.Equal(d.KeyHandle, other.KeyHandle) {
		return false
	}
	if !bytes.Equal(d.PubKey, other.PubKey) {
		return false
	}
	// Ignore the counter, it's a very dynamic value.
	return true
}

// GetU2FRegistration decodes the u2f registration data and builds the expected
// registration object.
func (d *U2FDevice) GetU2FRegistration() (*u2f.Registration, error) {
	pubKey, err := d.GetPubKeyDecoded()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &u2f.Registration{
		KeyHandle: d.KeyHandle,
		PubKey:    *pubKey,
	}, nil
}

// AuthPreferenceSpecSchemaTemplate is JSON schema for AuthPreferenceSpec
const AuthPreferenceSpecSchemaTemplate = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"type": {
			"type": "string"
		},
		"second_factor": {
			"type": "string"
		},
		"connector_name": {
			"type": "string"
		},
		"u2f": {
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"app_id": {
					"type": "string"
				},
				"facets": {
					"type": "array",
					"items": {
						"type": "string"
					}
				}
			}
		}%v
	}
}`

// LocalAuthSecretsSchema is a JSON schema for LocalAuthSecrets
const LocalAuthSecretsSchema = `{
	"type": "object",
	"additionalProperties": false,
	"properties": {
		"password_hash": {"type": "string"},
		"totp_key": {"type": "string"},
		"u2f_registration": {
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"raw": {"type": "string"},
				"key_handle": {"type": "string"},
				"pubkey": {"type": "string"}
			}
		},
		"u2f_counter": {"type": "number"},
		"mfa": {
			"type": "array",
			"items": {
				"type": "object",
				"additionalProperties": false,
				"properties": {
					"kind": {"type": "string"},
					"subKind": {"type": "string"},
					"version": {"type": "string"},
					"metadata": {
						"type": "object",
						"additionalProperties": false,
						"properties": {
							"Name": {"type": "string"},
							"Namespace": {"type": "string"}
						}
					},
					"id": {"type": "string"},
					"name": {"type": "string"},
					"addedAt": {"type": "string"},
					"lastUsed": {"type": "string"},
					"totp": {
						"type": "object",
						"additionalProperties": false,
						"properties": {
							"key": {"type": "string"}
						}
					},
					"u2f": {
						"type": "object",
						"additionalProperties": false,
						"properties": {
							"raw": {"type": "string"},
							"keyHandle": {"type": "string"},
							"pubKey": {"type": "string"},
							"counter": {"type": "number"}
						}
					}
				}
			}
		}
	}
}`

// GetAuthPreferenceSchema returns the schema with optionally injected
// schema for extensions.
func GetAuthPreferenceSchema(extensionSchema string) string {
	var authPreferenceSchema string
	if authPreferenceSchema == "" {
		authPreferenceSchema = fmt.Sprintf(AuthPreferenceSpecSchemaTemplate, "")
	} else {
		authPreferenceSchema = fmt.Sprintf(AuthPreferenceSpecSchemaTemplate, ","+extensionSchema)
	}
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, authPreferenceSchema, DefaultDefinitions)
}

// AuthPreferenceMarshaler implements marshal/unmarshal of AuthPreference implementations
// mostly adds support for extended versions.
type AuthPreferenceMarshaler interface {
	Marshal(c AuthPreference, opts ...MarshalOption) ([]byte, error)
	Unmarshal(bytes []byte, opts ...MarshalOption) (AuthPreference, error)
}

type teleportAuthPreferenceMarshaler struct{}

// Unmarshal unmarshals role from JSON or YAML.
func (t *teleportAuthPreferenceMarshaler) Unmarshal(bytes []byte, opts ...MarshalOption) (AuthPreference, error) {
	var authPreference AuthPreferenceV2

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(bytes, &authPreference); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	} else {
		err := utils.UnmarshalWithSchema(GetAuthPreferenceSchema(""), &authPreference, bytes)
		if err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	}
	if cfg.ID != 0 {
		authPreference.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		authPreference.SetExpiry(cfg.Expires)
	}
	return &authPreference, nil
}

// Marshal marshals role to JSON or YAML.
func (t *teleportAuthPreferenceMarshaler) Marshal(c AuthPreference, opts ...MarshalOption) ([]byte, error) {
	return json.Marshal(c)
}

var authPreferenceMarshaler AuthPreferenceMarshaler = &teleportAuthPreferenceMarshaler{}

// SetAuthPreferenceMarshaler sets global AuthPreferenceMarshaler
func SetAuthPreferenceMarshaler(m AuthPreferenceMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	authPreferenceMarshaler = m
}

// GetAuthPreferenceMarshaler returns currently set AuthPreferenceMarshaler
func GetAuthPreferenceMarshaler() AuthPreferenceMarshaler {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	return authPreferenceMarshaler
}
