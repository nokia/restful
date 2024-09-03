# Lambda Server

## Introduction

Lambda lets you focus on business logic.
HTTP + JSON are technical details, just like socket handling and forking on accepting a request.
These details are not in your way.
Lambda creates a new abstraction, making a server a collection of functions.
The concept is nothing new. It is somewhat similar to Python FastAPI with Pydantic.

Note that many lambda solutions are often meant to be serverless.
I.e. your app does not have an HTTP server, but functions directly invoked by an API GW.
This lambda solution adds server layer to your app. I.e. your app runs all the time, listening on a given port, like any other HTTP server.
To make your app serverless, thus be able to scale to zero instance, you may choose [Knative](https://knative.dev/).

## Your function as you wish

Lambda functions may look like this:

```go
f(ctx context.Context, TIn) (TOut, error)
```

All of these parameters are *optional*.

* `ctx` contains request context. Detailed later.
* `TIn` can be of any type, such as a structure. Represents the data the client sent as JSON, form data or in case of HTTP GET request query parameter.
* `TOut` can be of any type, such as a structure. That is sent as an answer JSON to client.
* `error` may be returned; if created by restful.NewError() then you can define HTTP status code. In non-error cases status code is automatic, 200/201/204.

## Example with JSON and Query

```go
package main

import (
    "context"
    "fmt"
    "net/http"

    "github.com/go-playground/validator/v10"
    "github.com/google/uuid"
    "github.com/nokia/restful"
    "github.com/sirupsen/logrus"
)

type userID struct {
    ID string `json:"id" validate:"uuid"`
}

type user struct {
    Name    string `json:"name" validate:"alpha,required"`
    Address string `json:"address,omitempty"`
}

var db = map[string]user{} // A simple in-memory database

func createUser(ctx context.Context, usr user) error {
    if usr.Name == "" {
        return restful.NewError(nil, http.StatusBadRequest, "Name not defined")
    }
    id := uuid.New().String()
    db[id] = usr
    l := restful.L(ctx)
    l.ResponseHeaderSet("Location", "http://localhost:8080/users?id="+id)
    return nil // No error
}

func readUser(id userID) (*user, error) {
    if usr, ok := db[id.ID]; ok {
        return &usr, nil
    }
    err := fmt.Errorf("invalid user id: %v", id.ID)
    return nil, restful.NewError(err, http.StatusBadRequest)
}

func main() {
    // Log requests.
    logrus.SetLevel(logrus.DebugLevel)

    // You may populate DB using 2 content types:
    // As application/json:
    //     curl -i http://localhost:8080/users --json '{"name": "Joe", "address": "Karakaari 7, 02610 Espoo, Suomi"}'
    // As application/x-www-form-urlencoded:
    //     curl -i http://localhost:8080/users -d "name=Jane" -d "address=Bokay Janos 36, 1083 Budapest, Hungary"
    restful.HandleFunc("/users", createUser).Methods(http.MethodPost)

    // Query using the URL/path returned in Location header
    // curl -s http://localhost:8080/users?id=<see Location header>
    restful.HandleFunc("/users", readUser).Methods(http.MethodGet)

    // Start the server
    restful.Start()
}
```

Notes:

* `Start` function starts your server, listening on port 8080.
* K8s liveness probe (/livez or /healthz) are answered automatically.
* Logs errors to stdout. If log level is debug, then log messages, too.
* `restful.L(ctx)` provides Lambda's HTTP request attributes, such as path parameters and method.
* Validate tagging is a convenient way of validating message content and returning HTTP status code 422 on error.
* On GET or POST with urlencoded parameters, [Gorilla/Schema](https://github.com/gorilla/schema) is used.
  If Go field names and parameter names do not match, use `schema:"query-parameter-name"` tagging.

## Example on using path-based parameters

```go
func readUser(ctx context.Context) (*user, error) {
    id := restful.L(ctx).RequestPathParameters()["id"]
    joe := user{Id: id, Name: "Joe", Address: "Karakaari 7, 02610 Espoo, Suomi"}
    return &joe, nil
}

func main() {
    restful.HandleFunc("/users/{id}", readUser).Methods(http.MethodGet) // curl -s http://localhost:8080/users/42
    restful.Start()
}
```

## Router, Port defined, Context propagation

```go
type user struct{ Name, Address string }
func validateUser(ctx context.Context, usr user) error {
    ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    return restful.Get(ctx, "https://httpbin.org/anything", &usr)
}

func newServer() *restful.Router {
    r := restful.NewRouter()
    r.HandleFunc("/users", validateUser).Methods(http.MethodPost, http.MethodPut) // curl http://localhost:8080/users -d 'Name=Joe' -d 'Address=Suomi'
    return r
}

func main() {
    newServer().ListenAndServe(":8080")
}

// In _test source:
func TestValidateUser(t *testing.T) {
    ctx := NewTestCtx("POST", "/users", nil /* no headers */, nil /* no vars */)
    joe := user{Name: "Joe", Address: "Karakaari 7, 02610 Espoo, Suomi"}
    assert.NoError(t, validateUser(ctx, joe))
}
```

Notes:

* You can test your lambda directly, using `NewTestCtx()`.
* Creating your own router instance is great when you test your code.
  You can call `ServeHTTP()` with standard [httptest](https://golang.org/pkg/net/http/httptest/) package.
  That may be more convenient when path or query variables are used, compared to creating test lambda context.
* You can define port at `ListenAndServe()`, if you do not like default 8080.
* Receiving context and passing that to client has several advantages.
  * You can define cancellation timeout.
  * Lambda context contains request information, including [tracing HTTP headers](tracing.md).
  * You can add header to HTTP response.

## Response status codes

Explicit status codes:

* When your lambda returns with error, that may use RESTful's errors.

    ```go
    func validateUser(ctx context.Context, usr user) error {
        err := errors.New("unknown user")
        return restful.NewError(err, http.StatusNotFound)
    }
    ```

* In successful cases status may be defined this way:

    ```go
    func validateUser(ctx context.Context, usr user) error {
        l := restful.L(ctx)
        l.ResponseStatus(http.StatusAccepted)
        return nil
    }
    ```

In most successful cases one lets RESTful set status code automatically.
The following rules are applied in this order:

* On `POST` request when `Location` header is present, `201 Created` is sent.
* When the response is empty, e.g. on successful `DELETE` operation without any content, `204 No Content` is sent.
* Otherwise `200 OK` is sent.

## Q&A

**Q: Where are the out-of-the-box middlewares like authorization, serving static files, etc?**

A: You are visiting the wrong project, maybe.
   This project is about being able to build cloud-native RESTful services.
   Leaving many things to other services, such as authorizing requests to API gateways.
   If you need those, you may want to check out [Fiber](https://github.com/gofiber/fiber).

**Q: Why is this library based on Gorilla/Mux, when there are other high-performance alternatives, such as [Gin](https://github.com/gin-gonic/gin) or [Bunrouter](https://bunrouter.uptrace.dev/)?**

A: We are fortunate to have so many great routers.
   Our aim is to have a simple syntax similar to standard http package.
   [Gorilla/Mux](https://github.com/gorilla/mux) delivers that with many great extensions.
   For a complex app with database operations, router speed difference may be negliable.

**Q: Is it possible to send alternative types in responses, decided run-time? Like `f() (T1, T2, error)`.**

A: At the moment it is not supported. But you can freely mix lambdas and http handler functions.
Alternatively, you may put T1 and T2 to a common T3 struct, e.g. as anonymous members.

**Q: Is it possible sending multi-part responses?**

A: Not supported. But you can freely mix lambdas and http handler functions.

**Q: Can one stream response? E.g. if response for request is to contain millions of database entries?**

A: Not supported. But you can freely mix lambdas and http handler functions. Base http package can do streaming wonderfully.

**Q: How to respond with binary content, such as downloading favicon or an image?**

A: Lambda serves primarily the purpose of JSON content. But you can freely mix lambdas and http handler functions. Base http package can send binary payload fine.
