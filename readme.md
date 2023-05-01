# Vault

This tool is used to handle automatic retrieval of secrets from Hashicorp vault

It uses a simple yml config to handle pulling the desired secrets.

Let's assume the following

```yml
secrets:
  version: 1.0.0
  collections:
    - name: test-aws
      output: ./.secrets.bat
      format: WINDOWS
      values: 
        - engine: aws
          namespace: admin
          path: /aws/dev/creds/22408000-lambda-deploy
    - name: test-kv
      output: ./.secrets.env
      values: 
        - engine: kv-v2
          root: kv-v2
          namespace: admin
          path: test/secret
          field: foo
          aliases: 
            - field: foo
              name: ${TEST_VAL}-val
        - engine: kv-v2
          root: kv-v2
          path: test/secret
```

Running `vault-env --collection test-kv` will output the file `./.secrets.env` as follows

```
MY_VAL-val="baz"
BAR="baz"
```

Assuming `TEST_VAL=MY_VAL` for the aliasing and the test/secret having the following shape 

```
{
  "bar": "baz"
}
```

These values in their dotenv file can then be easily ingested into the shell like so 

```bash
export $(xargs < ./.secrets.env )
```
or 
```bash
source ./.secrets.env
```

For windows systems you could do the following `vault-env --collection test-kv --output ./env.bat --format WINDOWS` to generate a bat file to set env vars

### Note 

You can optionally set `type: ENV` in your secret definition to emit it to stdout , eg `BAR="baz"` if you want to pipe the output


## Updating 

```
go get -u
go mod tidy
```

## Testing 

Install the following outside your module root

```bash
go install github.com/onsi/ginkgo/v2/ginkgo
go get github.com/onsi/gomega
```

Then run the following

```
ginkgo -r --tags=unit_test
```


## Build

This should produce binaries through the use of goreleaser at `./dist`

```bash
docker-compose run build
```

## Linting

```bash
docker-compose run lint
```

## Useful tools 

The following are useful for local debugging

- goweight - https://golangexample.com/a-tool-to-analyze-and-troubleshoot-a-go-binary-size/