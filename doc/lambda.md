# Lambda Server

## Introduction

Lambda lets you focus on business logic.
HTTP + JSON are technical details, just like socket handling and forking on accepting a request.
These unnecessary details are not in your way.
Lambda creates a new abstraction, making a server a collection of functions.
The concept is nothing new. The syntax offered here is similar to AWS Lambda Go handler.

Note that many lambda solutions are often meant to be serverless.
I.e. your app does not have an HTTP server, but functions directly invoked by an API GW.
This lambda solution adds a server layer to your app. I.e. your app runs all the time, like traditional servers.
To make your app serverless, thus scale with needs perfectly you may use [Knative](https://knative.dev/).

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

## Basic example

```go
type userId struct{ Id int }
type user struct{ Name, Address string }
func readUser(id userId) (*user, error) {
    if id.Id <= 0 {
        err := fmt.Errorf("invalid user id: %d", id.Id)
        return nil, restful.NewError(err, http.StatusBadRequest, "Bad requets")
    }
    joe := user{Id: id.Id, Name: "Joe", Address: "Karakaari 7, 02610 Espoo, Suomi"}
    return &joe, nil
}

func main() {
    restful.HandleFunc("/users", readUser).Methods(http.MethodGet) // curl http://localhost:8080/users?id=42
    restful.Start()
}
```

Notes:

* `Start` function starts your server, listening on port 8080.
* K8s liveness probe (/livez or /healthz) are answered automatically.
* Logs automatically.

## Context usage

```go
type user struct{ Id int, Name, Address string }
func readUser(ctx context.Context) (*user, error) {
    id := restful.L(ctx).RequestPathParameters()["id"]
    joe := user{Id: id, Name: "Joe", Address: "Karakaari 7, 02610 Espoo, Suomi"}
    return &joe, nil
}

func main() {
    restful.HandleFunc("/users/{id}", readUser).Methods(http.MethodGet) // curl http://localhost:8080/users/42
    restful.Start()
}
```

Note:

* `restful.L(ctx)` provides Lambda's HTTP request attributes, such as path parameters and method.

## Router, Port defined, Context propagation

```go
type user struct{ Name, Address string }
func createUser(ctx context.Context, usr user) error {
    ctx, _ = context.WithTimeout(ctx, 3*time.Second)

    if usr.Name == "" {
        return restful.NewError(nil, http.StatusBadRequest, "no name")
    }

    if err := restful.Get(ctx, "https://uservalidator.com", &usr); err != nil {
        return err
    }
    restful.L(ctx).ResponseHeaderSet("Location", "https://myserver.com/users/42")
    return nil
}

func TestCreateUser(t *testing.T) {
    assert := assert.New(t)
    ctx := NewTestCtx("POST", "/users", nil, nil)
    joe := user{Id: id, Name: "Joe", Address: "Karakaari 7, 02610 Espoo, Suomi"}
    assert.NoError(createUser(ctx, joe))
    assert.Equal("https://myserver.com/users/42", L(ctx).ResponseHeader().Get("Location"))
}

func newServer() *restful.Router {
    r := restful.NewRouter()
    r.HandleFunc("/users", createUser).Methods(http.MethodPost, http.MethodPut) // curl http://localhost:8080/users -d 'name=Joe' -d 'Address=Suomi'
    return r
}

func main() {
    newServer().ListenAndServe(":8080")
}
```

Notes:

* Creating your own router instance instead of using default one is great when you test your code. You can call `ServeHTTP()` with standard [httptest](https://golang.org/pkg/net/http/httptest/) package.
* You can test your lambda directly, using `NewTestCtx()`.
* You can define port at `ListenAndServe()`, if you do not like default 8080.
* Receiving context and passing that to client has several advantages.
  * You can define cancellation timeout.
  * Lambda context contains request information, including [tracing HTTP headers](tracing.md).
  * You can add header to HTTP response.

## Response status codes

Explicit status codes:

* When your lambda returns with error, that may use RESTful's errors.

    ```go
    func checkUser(ctx context.Context, usr user) error {
        err := errors.New("unknown user")
        return restful.NewError(err, http.StatusNotFound)
    }
    ```

* In successful cases status may be defined this way:

    ```go
    func checkUser(ctx context.Context, usr user) error {
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
