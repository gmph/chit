## Get started

1. To install dependencies, use `pip3 install -r requirements.txt`
2. To start the local dev server, use: `uvicorn main:app --reload`
3. Open the local dev server page in your browser
4. Navigate to `/set-password/{new_password}` to set up an admin password
5. Click on the 'Following' link
6. Enter `https://chit.grahammacphee.com` to follow your first chit site
7. Click on the 'Feed' link to return to your feed

## How it works

- See protocol.txt for the details of the chit protocol

## Deploy

You can also deploy your own instance to [Deta](https://deta.sh):

[![Deploy](https://button.deta.dev/1/svg)](https://go.deta.dev/deploy?repo=https://github.com/gmph/chit)

Follow the same instructions above from point #3 onwards.