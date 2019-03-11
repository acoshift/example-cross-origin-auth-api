# example-cross-origin-auth-api

Example Cross-Origin Auth and API Servers

## Steps

1. Generate RSA for sign JWT

	`make generate`
	
1. Start Auth Server

	`make start-auth`
	
1. Start API Server

	`make start-api`
	
1. Start Web Server

	`make start-web`

1. Browse web at http://localhost:8080

1. Sign In

1. You will sign in to localhost:8081, but profile api will called from localhost:8082
