package main

import (
	"log"
	"net/http"

	"github.com/gs-open-provider/poc-go-jwt/internal/configs"
	"github.com/gs-open-provider/poc-go-jwt/internal/logger"
	"github.com/gs-open-provider/poc-go-jwt/internal/services"
)

func main() {
	// Initialize Viper across the application
	configs.InitializeViper()

	// Initialize Logger across the application
	logger.InitializeZapCustomLogger()

	http.HandleFunc("/", services.HandleIndex)
	http.HandleFunc("/signin", services.Signin)
	http.HandleFunc("/welcome", services.Welcome)
	http.HandleFunc("/refresh", services.Refresh)

	log.Fatal(http.ListenAndServe(":9090", nil))
}
