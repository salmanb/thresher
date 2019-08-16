Utility to hit the threatstack REST API and pull a list of CVEs for Agents which match a set of supplied tags

Usage: ./thresher /where/to/store/files <tag1> <tag2> ...

Files are output to /where/to/store/files/<YYYY-MM-DD>/<instanceid>.html

Threatstack rate limits at 200 requests/minute. That is handled by calling a 2 minute sleep to let the window reset. 
Threatstack API also throws 500 errors pretty often, and we purposefully do not handle those gracefully at this time.

Authorization data is stored encrypted in auth.json -- KMS access is required to decrypt the file. File is encrypted with SOPS.

SOPS: https://github.com/mozilla/sops
