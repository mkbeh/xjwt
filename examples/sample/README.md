# Description

This is a sample REST API service implemented using jwt-go.

# Usage


Run main.go:

```
go run main.go
```

## Generate token

```shell
curl 'localhost:8080/create_token'
```

## Parse token

```shell
curl 'localhost:8080/parse_token' \
--header 'Authorization: Bearer <token>'
```