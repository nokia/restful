# RESTful Client

## Introduction

Client class is designed to send HTTP requests and receive their response.
Similar to `http.Client` class, with the difference of strong JSON support.

Functions have context parameters. That is used for generic purposes, such as cancelling a request or defining a timeout.
Furthermore RESTful's Server and Lambda class may add tracing information which is then propagated by this client.

## SendRecv

`SendRecv` function is at the heart of the client. It expects structure for data to be sent and received.

`SendRecv2xx` is its friend. It is almost the same, but returns error even if a response is received, but not 200-299.
`Get`, `Post` and other functions are built on top of it.

## POST, GET, PUT and DELETE

```go
type user struct{
    Name    string `json:"name,omitempty"`
    Address string `json:"addr,omitempty"`
}

client := restful.NewClient().Root("https://example.com") /* Setting API root is optional, may avoid passing config around. */
client.Timeout(5 * time.Second).Retry(3, time.Second, 5*time.Second)

joe := user{Name: "Joe", Address: "Karakaari 7, 02610 Espoo, Suomi"}
location, err := client.Post(ctx, "/user", &joe, nil /*no answer expected*/)
if err != nil {
    panic(err)
}

err = client.Get(ctx, location, &joe)
if err != nil {
    panic(err)
}

joe.Name = "Joe Smith"
_, err := client.Put(ctx, location, &joe, nil /*no answer expected*/)
if err != nil {
    panic(err)
}

err = client.Delete(location)
if err != nil {
    if restful.GetErrStatusCode(err) == http.StatusNotFound {
        panic("The user I've just created is not found. This is crazy.")
    }
    panic(err)
}
```

## HTTPS

### OS cert pool

HTTPS works out of box. Certs are loaded from OS cert pool without further ado.

```go
client := restful.NewClient()
```

### Own set of CA certs

Load CA certs from a directory. Looks for `*.crt` and `*.pem` files.
That is often needed when private CA is used.

```go
client := restful.NewClient().TLSRootCerts("/etc/cacerts")
```

### Mutual TLS

Mutual TLS is an advanced security solution for private networks. The server authenticates the client, too.

Load CA certs and load own `tls.key` and `tls.crt` files.
File naming follows Kubernetes TLS secret solution, e.g. used at `kubectl create secret tls` command.

```go
client := restful.NewClient()
client.TLSRootCerts("/etc/cacerts")
client.TLSOwnCerts("/etc/own_tls")
```

❗ Note that once the client loaded the key + cert that is in the memory.
Any update (e.g. cert-manager.io) will not affect that client.
You may restart your app, or in the cloud you may issue `kubectl rollout restart deploy/xxx`.

## Broadcast goodies

* `BroadcastRequest` sends a request to all IP addresses resolved for the given target URL, such as of Kubernetes headless service. Expects 2xx resposes for all.
* `SendRecvResolveFirst2xxSequential` and `SendRecvResolveFirst2xxParallel` are similar to the previous one, but the first 2xx answer satisfies them. Returns data of the first positive response. Sequential and parallel variants send requests one-by-one or all at the same time.
* `SendRecvListFirst2xxSequential` and `SendRecvListFirst2xxParallel` are similar to the previous one, but target URLs are defined as a list.
* `PingList` pings a list of URLs. Expects 2xx responses for all. No request body sent or received.
