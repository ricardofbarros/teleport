package main

import (
	"context"
	"log"
	"time"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

// rolesCRUD performs each roles crud function as an example
func roleCRUD(ctx context.Context, client *auth.Client) error {
	// create a new auditor role which has very limited permissions
	role, err := services.NewRole("auditor", services.RoleSpecV3{
		Options: services.RoleOptions{
			MaxSessionTTL: services.Duration(time.Hour),
		},
		Allow: services.RoleConditions{
			Logins: []string{"auditor"},
			Rules: []services.Rule{
				services.NewRule(services.KindSession, services.RO()),
			},
		},
		Deny: services.RoleConditions{
			NodeLabels: services.Labels{"*": []string{"*"}},
		},
	})
	if err != nil {
		trace.WrapWithMessage(err, "Failed to make new roe")
	}

	if err = client.UpsertRole(ctx, role); err != nil {
		trace.WrapWithMessage(err, "Failed to create role")
	}

	log.Printf("Created Role: %v", role.GetName())

	// defer deletion in case of an error below
	defer func() {
		// delete the auditor role we just created
		if err = client.DeleteRole(ctx, "auditor"); err != nil {
			log.Fatal(trace.WrapWithMessage(err, "Failed to delete role"))
		}

		log.Printf("Deleted role")
	}()

	// retrieve auditor role
	role, err = client.GetRole("auditor")
	if err != nil {
		trace.WrapWithMessage(err, "Failed to retrieve role for updatine")
	}

	log.Printf("Retrieved role: %v", role.GetName())

	// update the auditor role's ttl to one day
	role.SetOptions(services.RoleOptions{
		MaxSessionTTL: services.Duration(time.Hour * 24),
	})
	if err = client.UpsertRole(ctx, role); err != nil {
		trace.WrapWithMessage(err, "Failed to update role")
	}

	log.Printf("Updated role")
	return nil
}
