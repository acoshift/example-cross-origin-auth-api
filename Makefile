default:
	@echo "Example Cross-Origin Auth and API Servers"
	@echo "Commands:"
	@echo "\tgenerate - generate RSA for signing"
	@echo "\tstart-auth - start auth server at origin http://localhost:8081"
	@echo "\tstart-api - start api server at origin http://localhost:8082"
	@echo "\tstart-web - start web server at origin http://localhost:8080"

start-auth:
	go run ./auth

start-api:
	go run ./api

start-web:
	go run ./web

generate:
	openssl genrsa -out private-key.pem 2048
	openssl rsa -in private-key.pem -pubout > public-key.pem
