package fiberauth0

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber"
)

func parseOptions() {}

func validationKeyGetter(token *jwt.Token) (interface{}, error) {
	return []byte("My Secret"), nil
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
		if checkJWT(c) {
			c.Next()
		} else {
			c.Send("This route is protected.")
		}
	}
}
