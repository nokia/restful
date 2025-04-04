# Monitor

## Overview

Monitor is a middleware construct of the RESTful package.
It can be used to execute functions *pre* and *post* requests.
On the server, before and after handling a request.
On the client side, before sending a request and after receiving the response.

Monitor can be used for various purposes, such as logging, creating various metrics, service charging, message filtering, or authentication.

The concept is somewhat overlapping with container sidecars.
Sidecars are completely independent, can be added or removed, and are upgradeable independently.
But they are more expensive, may require network interface tweaking, and are problematic in serverless environments.
Monitor does not have these issues.

## Server

Monitor is available for `Server`, `Router`, and `Route` classes, including sub-routers.

The built-in `Logger` is based on Monitor.

```go
func pre(w http.ResponseWriter, r *http.Request) *http.Request {
    // Whatever to do before processing the request.
    fmt.Println("Begin")

    // If you write a response here, the handler function is not called.
    // Use it to terminate the request instead of letting it be served.
    if r.URL.Path == "/error" {
        w.WriteHeader(http.StatusBadRequest)
    }

    // You may return a new Request structure, e.g., altering the original context.
    // Or return nil if the original request is fine.
    return nil
}

func post(w http.ResponseWriter, r *http.Request, statusCode int) {
    // Whatever to do after processing the request.
    // You can use the status code.
    fmt.Println("Ended with ", statusCode)

    // If the pre function changed the context, e.g., added a new value, then r.Context() contains that change.
}

func main() {
    ...
    router := restful.NewRouter().Monitor(pre, post)
    ...
}
```

Monitor is practically a wrapper around the original handler functions.
You may apply several such wrappers.

```go
router = router.Monitor(pre1, post1).Monitor(pre2, nil).Monitor(nil, post3)
```

Monitor is quite similar to Middleware of Gorilla/Mux. The result is the same.
The original handler is wrapped by another handler.
The syntax is a bit different. Probably slightly more convenient in some cases,
especially when the status code of the wrapped handler is needed.

## Client

Client-side monitor is similar to server-side.
The interface is different.
Several Monitors can be added.

```go
func pre(req *http.Request) (*http.Response, error) {
    // If response or error is returned, then the intended request is not sent.
    if req.URL.Path == "/error" {
        return nil, errors.New("don't do that")
    } else if req.URL.Path == "/404" {
        return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Request: req}, nil
    }

    req.Header.Add("My-Header", "hello")
    return nil, nil
}

func post(req *http.Request, resp *http.Response, err error) *http.Response {
    if resp != nil && resp.StatusCode < 300 {
        fmt.Println("All went fine.")
    }
    return nil
}

func main() {
    client := restful.NewClient()
    client.Monitor(pre, post)
    err := client.Get(context.Background(), "https://example.com/data", nil)
    ...
}
```
