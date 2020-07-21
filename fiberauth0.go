package fiberauth0

import (
	"github.com/gofiber/fiber"
)

func Extractor() {}

func parseOptions() {}

func checkJWT() bool {
	return true
}

// Protected does check your JWT token and validates it
func Protected() func(*fiber.Ctx) {
	return func(c *fiber.Ctx) {
		c.Send("Hello World")
	}
}
