# Monitor

Monitor is a unique construct of RESTful package.
That can be used to execute functions *pre* and *post* calling handlers.
That is used by built-in `Logger` and can be utilized other ways, e.g. to create various metrics, service charging, filters, or authentication.

The concept is somewhat overlapping with container sidecars.
Sidecars are completely independent, therefore much better customizable and upgradeable.
But they are usually expensive, require network interface tweaking, and problematic in serverless environment.
Monitor does not have these issues.

Monitor is available for `Server`, `Router` and `Route` classes, including sub-routers.

```go
func pre(w http.ResponseWriter, r *http.Request) *http.Request {
    // Whatever to do before processing the request.
    fmt.Println("Begin")

    // If you write a response here, the handler function is not called.
    // Use it to terminate the request instead of let it being served.
    if r.URL.Path == "/error" {
        w.WriteHeader(http.StatusBadRequest)
    }

    // You may return a new Request structure, e.g. altering the original context.
    // Or return nil if the original request is fine.
    return nil
}

func post(w http.ResponseWriter, r *http.Request, statusCode int) {
    // Whatever to do after processing the request.
    // You can use the status code.
    fmt.Println("Ended with ", statusCode)

    // If the pre function changed the context, e.g. added a new value, then r.Context() contains that change.
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
