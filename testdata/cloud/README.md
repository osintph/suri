# Cloud Storage Check - Test Target Setup

This directory documents how to prepare deliberately misconfigured cloud storage
buckets for integration testing of the cloud check module. Unit tests use
`httptest.NewServer` (see `internal/checks/cloud/cloud_test.go`) and do not
require any external infrastructure. The targets described below are for manual
operator verification only.

You must own or have explicit written authorisation to misconfigure the buckets
below. Do not probe any bucket you do not control.

---

## AWS S3

### Create a public bucket

```bash
BUCKET=suri-test-public-$(date +%s)
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1

# Disable Block Public Access (required before applying a public bucket policy).
aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

# Apply an anonymous list policy.
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid":       "PublicList",
    "Effect":    "Allow",
    "Principal": "*",
    "Action":    "s3:ListBucket",
    "Resource":  "arn:aws:s3:::$BUCKET"
  }]
}
EOF
)"
echo "Test bucket: $BUCKET.s3.amazonaws.com"
```

### Scope file entry

Add to your engagement scope file:

```toml
cloud_buckets = [
  "*.s3.amazonaws.com",
  "*.s3.*.amazonaws.com",
]
```

### Run the check

```bash
./suri scan \
  --scope path/to/scope.toml \
  --domain example.com \
  --db /tmp/cloud-test.db \
  https://example.com
```

Expected output: at least one finding with check_id `cloud.s3.public-list`.

### Teardown

```bash
aws s3 rb "s3://$BUCKET" --force
```

---

## Azure Blob Storage

### Create a public container

```bash
ACCOUNT=suritest$(date +%s | tail -c 8)
CONTAINER=public
RGROUP=suri-test-rg
LOCATION=eastus

az group create --name "$RGROUP" --location "$LOCATION"
az storage account create \
  --name "$ACCOUNT" \
  --resource-group "$RGROUP" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --allow-blob-public-access true

CONN=$(az storage account show-connection-string \
  --name "$ACCOUNT" --resource-group "$RGROUP" --query connectionString -o tsv)

az storage container create \
  --name "$CONTAINER" \
  --connection-string "$CONN" \
  --public-access container

echo "Test endpoint: https://$ACCOUNT.blob.core.windows.net/$CONTAINER"
```

### Scope file entry

```toml
cloud_buckets = [
  "*.blob.core.windows.net",
]
```

### Teardown

```bash
az group delete --name "$RGROUP" --yes --no-wait
```

---

## Google Cloud Storage

### Create a public bucket

```bash
PROJECT=$(gcloud config get-value project)
BUCKET=suri-test-$(date +%s)

gsutil mb -p "$PROJECT" "gs://$BUCKET"
gsutil iam ch allUsers:objectViewer "gs://$BUCKET"
gsutil acl set public-read "gs://$BUCKET"

echo "Test URL: https://storage.googleapis.com/$BUCKET"
```

### Scope file entry

```toml
cloud_buckets = [
  "storage.googleapis.com",
]
```

### Teardown

```bash
gsutil rb "gs://$BUCKET"
```

---

## Expected findings in the database

After a successful integration run, query the SQLite database:

```bash
sqlite3 /tmp/cloud-test.db \
  "SELECT check_id, severity, url FROM findings ORDER BY check_id;"
```

You should see rows with check IDs matching the exposed buckets:
- `cloud.s3.public-list`
- `cloud.azure.public-container`
- `cloud.gcs.public-bucket`
