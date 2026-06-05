# Kinra Backend

This is Kinra's server-side API for account auth, PSA cert lookup, and market data aggregation. The iOS app should never contain PSA, eBay, TCGplayer, RapidAPI, or database credentials. Kinra calls this backend, and this backend calls external providers.

## API Routes

```text
GET  /health
GET  /auth/usernames/{username}?available=true
POST /auth/register
POST /auth/login
POST /auth/federated
GET  /auth/me
GET  /psa/certs/{certNumber}
POST /market/quote
GET  /market/quote
GET  /tcgplayer/pricing/...
```

Auth responses match the iOS app's `KinraAuthenticatedAccount` model:

```json
{
  "userID": "uuid",
  "name": "Jeffrey Yang",
  "username": "jeffrey",
  "email": "jeffrey@example.com",
  "phone": "+15555551234",
  "sessionToken": "kinra_..."
}
```

Passwords are hashed with Node's built-in `scrypt`. Session tokens are returned once to the app and stored on the server only as SHA-256 hashes.

## Local Setup

1. Rotate any PSA token that was pasted into chat or logs.
2. Copy the example env file:

```sh
cp .env.example .env
```

3. Configure account auth:

```sh
AUTH_DATA_PATH=./data/kinra-auth.json
SESSION_TTL_HOURS=2160
APPLE_BUNDLE_ID=com.jeffreyyang.saku
APPLE_SERVICE_ID=
```

`AUTH_DATA_PATH` is fine for local and a single-node beta server with a persistent disk. For a larger production backend, replace the storage layer with Postgres/Supabase/Neon so accounts persist across deploys and multiple instances.

4. Configure provider credentials as needed. For PSA cert lookup:

```sh
PSA_TOKEN_URL=
PSA_API_BASE_URL=https://api.psacard.com
PSA_CERT_PATH_TEMPLATE=/publicapi/cert/GetByCertNumber/{certNumber}
PSA_CERT_IMAGES_PATH_TEMPLATE=/publicapi/cert/GetImagesByCertNumber/{certNumber}
PSA_USERNAME=
PSA_PASSWORD=
PSA_CLIENT_ID=
PSA_CLIENT_SECRET=
```

If PSA gives you a temporary access token for smoke testing, you can set `PSA_ACCESS_TOKEN`, but do not use that for production.

For live market aggregation:

```sh
EBAY_CLIENT_ID=
EBAY_CLIENT_SECRET=
EBAY_MARKETPLACE_ID=EBAY_US
EBAY_ENABLE_MARKETPLACE_INSIGHTS=false

TCGPLAYER_PUBLIC_KEY=
TCGPLAYER_PRIVATE_KEY=
TCGPLAYER_PRICING_BASE_URL=https://api.tcgplayer.com/pricing

GRADED_CENSUS_RAPIDAPI_KEY=
GRADED_CENSUS_RAPIDAPI_HOST=graded-card-census-api.p.rapidapi.com
GRADED_CENSUS_API_BASE_URL=https://graded-card-census-api.p.rapidapi.com
```

5. Start the backend:

```sh
npm run dev
```

6. Test health:

```sh
curl http://127.0.0.1:8787/health
```

7. Test auth:

```sh
curl -X POST http://127.0.0.1:8787/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Jeffrey Yang",
    "username": "jeffreytest",
    "email": "jeffrey@example.com",
    "phone": "+15555551234",
    "password": "replace-with-a-long-password"
  }'

curl -X POST http://127.0.0.1:8787/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "jeffrey@example.com",
    "password": "replace-with-a-long-password"
  }'
```

8. Test a PSA cert:

```sh
curl http://127.0.0.1:8787/psa/certs/12345678
```

9. Test market quote aggregation:

```sh
curl -X POST http://127.0.0.1:8787/market/quote \
  -H 'Content-Type: application/json' \
  -d '{
    "game": "Pokémon",
    "name": "Latios",
    "set_name": "Paradise Dragona",
    "number": "070/064",
    "condition_grade": "PSA 10",
    "certification_number": "98988567"
  }'
```

## iOS Configuration

Set these in `Saku/Info.plist` to your backend URL:

```text
KINRA_AUTH_API_BASE_URL
SAKU_PSA_CERT_API_BASE_URL
SAKU_MARKET_API_BASE_URL
```

For local simulator testing:

```text
http://127.0.0.1:8787
```

For production, use an HTTPS URL, for example:

```text
https://api.kinra.app
```

Release builds intentionally ignore non-HTTPS, localhost, `.local`, and private-IP API base URLs.

## Market Quote Response

Market quotes are returned as:

```json
{
  "quote": {
    "blendedValueUSD": 124.5,
    "estimatedLowUSD": 118,
    "estimatedHighUSD": 132,
    "lastVerifiedSaleUSD": 126,
    "activeListingFloorUSD": 121,
    "medianActiveListingUSD": 129,
    "activeListingCount": 8,
    "verifiedCompCount90Day": 4,
    "liquidityScore": 47,
    "sellerCount": 6,
    "sources": [
      {
        "name": "eBay",
        "basis": "Active listing median",
        "valueUSD": 129,
        "observedAt": "2026-05-19T00:00:00.000Z"
      }
    ],
    "comps": [],
    "listingBands": [],
    "conditionBands": [],
    "saleFormatBands": [],
    "rawGradedRows": [],
    "conditionRows": []
  }
}
```

If no configured provider returns usable pricing, the backend returns `404 market_data_unavailable`. The app then shows its unavailable state instead of inventing market data.

## Provider Notes

- PSA cert data uses PSA's public API with `Authorization: bearer <access token>`.
- Public/no-credential pricing currently uses Pokémon TCG API when a selected item matches that catalog.
- eBay active supply uses the Buy Browse API `item_summary/search`.
- eBay sold comps require Marketplace Insights access, which is limited access. Leave `EBAY_ENABLE_MARKETPLACE_INSIGHTS=false` unless your eBay app is approved.
- TCGplayer pricing requires existing developer API access.
- PSA population reports use RapidAPI's Graded Card Census API.

## TCGplayer Pricing Proxy Routes

These routes keep the TCGplayer bearer token on the server and forward the pricing response back to Kinra:

```text
GET /tcgplayer/pricing/marketprices/{productconditionId}
GET /tcgplayer/pricing/group/{groupId}
GET /tcgplayer/pricing/product/{productIds}
GET /tcgplayer/pricing/sku/{skuIds}
GET /tcgplayer/pricing/buy/product/{productIds}
GET /tcgplayer/pricing/buy/sku/{skuIds}
GET /tcgplayer/pricing/buy/group/{groupId}
```
