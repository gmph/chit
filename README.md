## Get started

- To install dependencies, use: pip3 install "fastapi[all]"
- To start the dev server, use: `uvicorn main:app --reload`

## File structure

#### main.py

The chit Python server

#### password.txt

A one-line text file with the admin password in plaintext (very secure...)

#### posts.txt

A multi-line text file with all posts for this chit site, in the format:

```
[1668285230666]
This is the text content of a post
```

i.e. Unix miliseconds in square brackets, followed by a new line, followed by the post text.

#### following.txt

A multi-line text file which lists URLs of other chit sites this one is following. Valid chit root URLs only. One URL per line.

#### followers.txt

A multi-line text file which lists URLs of other chit sites that follow this one. Valid chit root URLs only. One URL per line.