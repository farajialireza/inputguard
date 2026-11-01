package main

import (
	"log"
	"net/http"

	"github.com/farajialireza/inputguard/internal/api"
)

func main() {
	router := api.NewRouter()

	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	log.Println("InputGuard API listening on :8080")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

