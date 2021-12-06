package schema

import (
	"crypto/ecdsa"
	"time"

	cfcrypto "github.com/common-fate/cfcrypto"
)

type Actors struct {
	User           User           `json:"user"`
	IdentityServer IdentityServer `json:"identityServer"`
}

type User struct {
	ID        string
	PublicKey ecdsa.PublicKey
}

type IdentityServer struct {
	PublicKey ecdsa.PublicKey
}

// Facts are data which we *know* to be true
// Facts MUST be sourced from the user's cloud infrastructure
// we can't rely on Facts provided by any client (user, admin, nor Common Fate)
type Facts struct {
	Actors Actors    `json:"actors"`
	Time   time.Time `json:"time"`
}

type SerialisedFacts struct {
	Actors SerialisedActors
	Time   time.Time `json:"time"`
}

type SerialisedActors struct {
	User           SerialisedUser
	IdentityServer SerialisedIdentityServer
}

type SerialisedUser struct {
	ID        string
	PublicKey []byte
}

type SerialisedIdentityServer struct {
	PublicKey []byte
}

func (f *Facts) Serialise() (*SerialisedFacts, error) {
	userBytes, err := cfcrypto.MarshalECDSAPublicKey(&f.Actors.User.PublicKey)
	if err != nil {
		return nil, err
	}
	idBytes, err := cfcrypto.MarshalECDSAPublicKey(&f.Actors.IdentityServer.PublicKey)
	if err != nil {
		return nil, err
	}

	sf := SerialisedFacts{
		Actors: SerialisedActors{
			User: SerialisedUser{
				ID:        f.Actors.User.ID,
				PublicKey: userBytes,
			},
			IdentityServer: SerialisedIdentityServer{
				PublicKey: idBytes,
			},
		},
	}
	return &sf, nil
}

func (sf *SerialisedFacts) Deserialise() (*Facts, error) {
	userKey, err := cfcrypto.ParseECDSAPublicKey(sf.Actors.User.PublicKey)
	if err != nil {
		return nil, err
	}
	idKey, err := cfcrypto.ParseECDSAPublicKey(sf.Actors.IdentityServer.PublicKey)
	if err != nil {
		return nil, err
	}

	f := Facts{
		Actors: Actors{
			User: User{
				ID:        sf.Actors.User.ID,
				PublicKey: *userKey,
			},
			IdentityServer: IdentityServer{
				PublicKey: *idKey,
			},
		},
	}

	return &f, nil
}
