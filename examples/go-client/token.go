package main

import (
	"context"
	"log"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/trace"
)

// tokenCRUD performs each token crud function as an example.
func tokenCRUD(ctx context.Context, client *auth.Client) error {
	// create a randomly generated token for proxy servers to join the cluster with
	tokenString, err := client.GenerateToken(ctx, auth.GenerateTokenRequest{
		Roles: teleport.Roles{teleport.RoleProxy},
		TTL:   time.Hour,
	})
	if err != nil {
		trace.WrapWithMessage(err, "Failed to generate token")
	}

	log.Printf("Generated token: %v", tokenString)

	// defer deletion in case of an error below
	defer func() {
		// delete token
		if err = client.DeleteToken(tokenString); err != nil {
			log.Fatal(trace.WrapWithMessage(err, "Failed to delete token"))
		}

		log.Println("Deleted token")
	}()

	// retrieve token
	token, err := client.GetToken(tokenString)
	if err != nil {
		trace.WrapWithMessage(err, "Failed to retrieve token for update")
	}

	log.Printf("Retrieved token: %v", token.GetName())

	// update the token to be expired
	token.SetExpiry(time.Now())
	if err = client.UpsertToken(token); err != nil {
		trace.WrapWithMessage(err, "Failed to update token")
	}

	log.Println("Updated token")
	return nil
}
