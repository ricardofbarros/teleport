package main

import (
	"context"
	"log"
	"time"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

// accessWorkflow performs the necessary access management functions as an example
func accessWorkflow(ctx context.Context, client *auth.Client) error {
	// create user example, which will be used to make an access request
	user, _ := services.NewUser("example")
	if err := client.CreateUser(ctx, user); err != nil {
		return trace.WrapWithMessage(err, "Failed to create new user")
	}

	// defer deletion in case of an error below
	defer func() {
		// delete user
		if err := client.DeleteUser(ctx, user.GetName()); err != nil {
			log.Fatal(trace.WrapWithMessage(err, "Failed to delete user"))
		}

		log.Println("Deleted user")
	}()

	// create access request for example to temporarily use the admin role in the cluster
	accessReq, err := services.NewAccessRequest("example", "admin")
	if err != nil {
		return trace.WrapWithMessage(err, "Failed to make new access request")
	}

	// use AccessRequest setters to set optional fields
	accessReq.SetAccessExpiry(time.Now().Add(time.Hour))
	accessReq.SetRequestReason("I need more power.")
	accessReq.SetSystemAnnotations(map[string][]string{
		"ticket": {"137"},
	})

	if err = client.CreateAccessRequest(ctx, accessReq); err != nil {
		return trace.WrapWithMessage(err, "Failed to create access request")
	}

	log.Printf("Created access request: %v", accessReq)

	// defer deletion in case of an error below
	defer func() {
		// delete access request
		if err = client.DeleteAccessRequest(ctx, accessReq.GetName()); err != nil {
			log.Fatal(trace.WrapWithMessage(err, "Failed to delete access request"))
		}

		log.Println("Deleted access request")
	}()

	// retrieve all pending access requests
	filter := services.AccessRequestFilter{State: services.RequestState_PENDING}
	accessReqs, err := client.GetAccessRequests(ctx, filter)
	if err != nil {
		return trace.Wrap(err, "Failed to retrieve access requests: %v", accessReqs)
	}

	log.Println("Retrieved access requests:")
	for _, a := range accessReqs {
		log.Printf("  %v", a)
	}

	// approve access request
	if err = client.SetAccessRequestState(ctx, services.AccessRequestUpdate{
		RequestID: accessReq.GetName(),
		State:     services.RequestState_APPROVED,
		Reason:    "seems legit",
		// Roles: If you don't want to grant all the roles requested,
		// you can provide a subset of role with the Roles field.
	}); err != nil {
		return trace.WrapWithMessage(err, "Failed to accept request")
	}

	log.Println("Approved access request")

	// deny access request
	if err = client.SetAccessRequestState(ctx, services.AccessRequestUpdate{
		RequestID: accessReq.GetName(),
		State:     services.RequestState_DENIED,
		Reason:    "not today",
	}); err != nil {
		return trace.WrapWithMessage(err, "Failed to deny request")
	}

	log.Println("Denied access request")
	return nil
}
