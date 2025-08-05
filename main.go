package main

import (
	"log"

	"github.com/tech-manthan/secure-auth/db"
	"github.com/tech-manthan/secure-auth/server"
	myjwt "github.com/tech-manthan/secure-auth/server/middleware/myJwt"
)

const (
	host = "localhost"
	port = "9000"
)

func main() {
	db.InitDB()

	jwtErr := myjwt.InitJWT()

	if jwtErr != nil {
		log.Println("Error initializing the JWT!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)

	if serverErr != nil {
		log.Println("Error starting the server!")
		log.Fatal(serverErr)
	}
}
