# Error

RESTful's Error is a construct meeting Go `error` interface.
It contains HTTP status code besides traditional error.

Best used with [Lambda](lambda.md), providing a smooth way of returning an HTTP status code.

```go
func handlerX(ctx context.Context) (*myStruct, error) {
    data, err := f(ctx)
    if err != nil {
        return nil, restful.NewError(err, http.StatusBadRequest) // Return the whole error to the client.
    }
    return data, nil
}
```

One may hide the details and send a simpler response.

```go
func handlerY(ctx context.Context) (*myStruct, error) {
    data, err := f(ctx)
    if err != nil {
        fmt.Print(err) // Log detailed error.
        return nil, restful.NewError(nil, http.StatusBadRequest, "Bad Request") // Return a simpler message only.
    }
    return data, nil
}
```

RESTful's HTTP [Client](client.md) returns RESTful's Error object.
Therefore HTTP status code can be checked.

```go
func handlerZ(ctx context.Context) (*myStruct, error) {
    var data myStruct
    err := restful.NewClient().Get(ctx, "https://example.com", &data)
    if err != nil {
        if restful.IsConnectError(err) {
            fmt.Print("Connection failed")
        } else if restful.GetErrStatusCode(err) == http.StatusUnauthorized {
            fmt.Print("We should have got authorized, first.")
        }
        return nil, err
    }
    return &data, nil
}
```
