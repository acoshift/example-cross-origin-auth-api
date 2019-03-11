package main

import (
	"io"
	"log"
	"net/http"
)

func main() {
	log.Println("Web Server started at :8080")
	http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, index)
	}))
}

// language=HTML
const index = `
<!doctype html>
<title>Example Cross-Origin Auth and API Servers</title>
<h1>Example Cross-Origin Auth and API Servers</h1>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>

<div id="app" style="display: none;">
	<div id="signIn">
		<form class="js-signIn">
			<label for="username">Username</label>
			<input id="username" name="username" value="miku">
			<br>
			<label for="password">Password</label>
			<input id="password" name="password" type="password" value="nakano">
			<br>
			<button>Sign In</button>
		</form>
	</div>

	<div id="main">
		<h2>Welcome, <span id="name"></span>!</h2>
		<button class="js-signOut">Sign Out</button>
	</div>
</div>

<script>
	;(async function () {
		let _token = ''
		let _token_expires = 0
		
		async function getToken () {
			if (_token && Date.now() < _token_expires - 5000) {
				return _token
			}
			
			try {
				const resp = await fetch('http://localhost:8081/token', {
					credentials: 'include',
					headers: new Headers({
						'X-Requested-With': 'XMLHttpRequest'
					})
				})
				const body = await resp.json()
				_token = body['access_token'] || ''
				_token_expires = Date.now() + (body['expires_in'] * 1000)
				return _token
			} catch (e) {
				return ''
			}
		}
		
		async function isSignedIn () {
			const token = await getToken()
			return !!token
		}
		
		async function signIn (username, password) {
			try {
				const resp = await fetch('http://localhost:8081/signin', {
					method: 'POST',
					credentials: 'include',
					body: 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password),
					headers: new Headers({
						'X-Requested-With': 'XMLHttpRequest',
						'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'
					})
				})
				const body = await resp.json()
				return !!body.success
			} catch (e) {
				console.error(e)
				return false
			}
		}
		
		async function signOut () {
			try {
				const resp = await fetch('http://localhost:8081/signout', {
					method: 'POST',
					credentials: 'include',
					headers: new Headers({
						'X-Requested-With': 'XMLHttpRequest'
					})
				})
				const body = await resp.json()
				return !!body.success
			} catch (e) {
				console.error(e)
				return false
			}
		}
		
		async function profile () {
			const token = await getToken()
			if (!token) {
				return null
			}
			
			try {
				const resp = await fetch('http://localhost:8082/profile', {
					headers: new Headers({
						'Authorization': 'Bearer ' + token
					})
				})
				return await resp.json()
			} catch (e) {
				console.error(e)
				return null
			}
		}
		
	 	if (await isSignedIn()) {
	 		$('#signIn').hide()
	 		$('#main').show()
	 		
	 		profile()
	 			.then((data) => {
	 				console.log(data)
	 				if (data == null) {
	 					// maybe session expired, need to re-login
	 					location.reload()
	 					return
	 				}
	 				
	 				$('#name').text(data.name)
	 			})
	 	} else {
	 		$('#signIn').show()
	 		$('#main').hide()
	 	}
	 	
	 	const $signIn = $('.js-signIn')
	 	$signIn.on('submit', (event) => {
	 		event.preventDefault()
	 		
	 		const username = $signIn.find('[name=username]').val()
	 		const password = $signIn.find('[name=password]').val()
	 		signIn(username, password)
	 			.then((success) => {
	 				if (success) {
	 					location.reload()
	 				} else {
	 					throw new Error('oh yeah!')
	 				}
	 			}).catch(() => {
	 				alert('invalid credentials!')
	 			})
	 		return false
	 	})
	 	
	 	$('.js-signOut').on('click', () => {
	 		signOut()
	 			.then((success) => {
	 				if (success) {
	 					location.reload()
	 				} else {
	 					throw new Error('oh my loli!')
	 				}
	 			}).catch(() => {
	 				alert('can not sign out, try again now :D')
	 			})
	 	})
	 	
	 	$('#app').show()
	})()
</script>
`
