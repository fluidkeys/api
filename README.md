# Key directory

## Get a public key

Get a verified OpenPGP public key for the email address:

```
GET /emails/:email/key
```

### Parameters

| Name        | Type   | Description                                       |
|-------------|--------|----------------------------------------------------
| email       | string | **Required.** urlencoded email address            |

### Response

```
Status: 200 Found
Content-Type: application/json

{
    "armoredPublicKey": "--- BEGIN PGP PUBLIC KEY ---"
}
```

### Example

```
curl https://api.fluidkeys.com/v1/email/tina@example.com/key
```

# Secrets

## Send a secret to a public key

```
POST /secrets
```

### Parameters

| Name                     | Type   | Description |
|--------------------------|--------|-------------|
| `recipientFingerprint`   | string | **Required.** The fingerprint of the key to send the secret to, prepended with `OPENPGP4FPR:`
| `armoredEncryptedSecret` | string | **Required.** ASCII-armored encrypted PGP secret data.

### Example

```
curl -v -X POST -H "Content-Type: application/json" https://api.fluidkeys.com/v1/secrets --data @- << EOF
{
    "recipientFingerprint": "OPENPGP4FPR:AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB",
    "armoredEncryptedSecret": "---- BEGIN PGP MESSAGE --- ..."
}
EOF
```

### Response

```
Status: 201 Created
```

## List your secrets

List the stored encrypted secrets for the authenticated public key:

```
GET /secrets
```

### Authentication

The call must be authenticated with a public key.

### Example

```
curl -v -H "Authorization: tmpfingerprint: OPENPGP4FPR:AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB" https://api.fluidkeys.com/v1/secrets

---
200 Found
{
    "secrets": [{
        "encryptedMetadata": "<ASCII armored PGP message>"
        "encryptedContent": "<ASCII armored PGP message>",
    }],

}
```

`encryptedMetadata` is encrypted to the public key. Inside it contains e.g.:

```
{
    "secretUuid": "8ef46a96-f735-11e8-a220-7fd225378c68",
}
```

`encryptedContent` contains a base64 encoded PGP message containing the content of the secret.

Future versions may omit `encryptedContent` and specify a download URL.

## Delete a secret

Delete a secret by its unique ID:

```
DELETE /secrets/:uuid
```

### Authentication

The call must be authenticated as the key that is the recipient of the secret.

### Parameters

| Name       | Type | Description                                       |
|------------|------|----------------------------------------------------
| uuid       | uuid | **Required.** The UUID of the secret to delete


### Response


```
202 Accepted
```

### Example

```
DELETE https://api.fluidkeys.com/v1/secrets/8ef46a96-f735-11e8-a220-7fd225378c68
Authorization: tmpfingerprint: OPENPGP4FPR:AAAABBBBAAAABBBBAAAABBBBAAAABBBBAAAABBBB
---
202 Accepted
```
