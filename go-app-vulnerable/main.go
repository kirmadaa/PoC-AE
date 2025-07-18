package main

import (
	"fmt"
	"log"
	"net/http"

	// This dependency is chosen as it often has vulnerabilities reported by Trivy for older versions.
	// We'll intentionally use an older, vulnerable version in go.mod.
	// For actual vulnerabilities, you'd check a CVE database.
	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("Starting vulnerable Go application...")

	// Initialize gin with a vulnerable version to trigger Trivy.
	// As of this writing (July 2025), older Gin versions likely have known CVEs.
	// We'll rely on go.mod for the version.
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello from vulnerable Go app!",
		})
	})

	log.Fatal(router.Run(":8080"))
}