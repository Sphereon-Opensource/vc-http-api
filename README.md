VC HTTP API
==================================

A VC HTTP API implemented as per the [W3C-CCG specification](https://w3c-ccg.github.io/vc-http-api/).


Getting Started
---------------

```sh

# Install dependencies
npm install

# Start development live-reload server
PORT=8080 npm run dev

# Start production server:
PORT=8080 npm start
```
Docker Support
------
```sh

# Build your docker
docker build -t sphereon/vc-http-api .
#            ^      ^           ^
#          tag  tag name      Dockerfile location

# run your docker
docker run -p 8080:8080 sphereon/vc-http-api
#                 ^            ^
#          bind the port    container tag
#          to your host
#          machine port   

