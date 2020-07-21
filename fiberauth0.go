package fiberauth0

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber"
	"github.com/joho/godotenv"
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func parseOptions() {}

func validationKeyGetter(token *jwt.Token) (interface{}, error) {
	// Verify 'aud' claim
	aud := os.Getenv("AUDIENCE")
	checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
	if !checkAud {
		return token, errors.New("Invalid audience.")
	}
	// Verify 'iss' claim
	iss := os.Getenv("AUTHORITY")
	checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
	if !checkIss {
		return token, errors.New("Invalid issuer.")
	}

	cert, err := getPemCert(token)
	if err != nil {
		return nil, err
	}

	result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	return result, nil
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get(os.Getenv("AUTHORITY") + ".well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}

func extractor(c *fiber.Ctx) (string, error) {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return "", nil
	}
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}
	return authHeaderParts[1], nil
}

func checkJWT(c *fiber.Ctx) bool {
	token, err := extractor(c)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return false
	}

	parsedToken, err := jwt.Parse(token, validationKeyGetter)
	if err != nil {
		fmt.Printf("Error parsing token: %v", err)
		return false
	}

	return parsedToken.Valid
}

// Protected does check your JWT token and validates it
func Protected() func(*fiber.Ctx) {

	return func(c *fiber.Ctx) {
		err := godotenv.Load()
		if err != nil {
			log.Fatalf("Error loading .env file")
			fmt.Println("Error loading .env file")
			c.Send("")
		}
		if checkJWT(c) {
			c.Next()
		} else {
			c.Send("This route is protected.")
		}
	}
}
