package main

import (
	"github.com/gs-open-provider/poc-go-jwt/internal/configs"
	"github.com/gs-open-provider/poc-go-jwt/internal/logger"
)

func main() {
	// Initialize Viper across the application
	configs.InitializeViper()

	// Initialize Logger across the application
	logger.InitializeZapCustomLogger()
}
