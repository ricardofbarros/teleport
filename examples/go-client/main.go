/*
Copyright 2018-2021 Gravitational, Inc.

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

package main

import (
	"context"
	"log"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

func main() {
	ctx := context.Background()
	log.Printf("Starting Teleport client...")

	client, err := auth.NewClient(client.Config{
		// TODO: Can Addrs be loaded from somewhere?
		Addrs:       []string{"proxy.example.com:3025"},
		Credentials: client.ProfileCreds(),
		// Credentials: client.IdentityCreds("/home/bjoerger/dev"),
		// Credentials: client.PathCreds("certs/api-admin"),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// create user example, which will be used to make an access request
	user, _ := services.NewUser("example")
	if err := client.CreateUser(ctx, user); err != nil {
		log.Fatal("Failed to create new user")
	}

	// defer deletion in case of an error below
	defer func() {
		// delete user
		if err := client.DeleteUser(ctx, user.GetName()); err != nil {
			log.Fatal(trace.WrapWithMessage(err, "Failed to delete user"))
		}

		log.Println("Deleted user")
	}()
}
