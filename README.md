# fiberauth0
A plug-and-play middleware to secure your fiber API with auth0

## Usage
The go script loads the 2 important Statements from an ".env" file which has to be in project path.

```env
AUDIENCE=http://localhost:3000
AUTHORITY=https://dev-xxxxxx.eu.auth0.com/
```

 ## Simple example

 ```go
package main

import (
	fiberauth0 "github.com/Mechse/fiberauth0"
	fiber "github.com/gofiber/fiber"
)

func helloWorld(c *fiber.Ctx) {
	c.Send("Welcome to this protected root.")
}

func main() {
	app := fiber.New()
	app.Get("/", fiberauth0.Protected(), helloWorld)
	app.Listen(3000)
}
 ```