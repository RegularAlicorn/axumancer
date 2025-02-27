document.addEventListener("DOMContentLoaded", function() {
    add_event_signin_form()
    add_event_register_form()
})

function add_event_signin_form() {
    // We have the login button disabled, enabling once we loaded our javascript
    // THIS IS AN ISSUE, IF THE OTHER PARTY DOES NOT LOAD JAVASCRIPT
    var signin_submit_btn = document.getElementById("signin_submit")
    if(signin_submit_btn) {
        signin_submit_btn.disabled = false
    }
    var signin_form = document.getElementById("signin_form")
    if(signin_form) {
        signin_form.addEventListener("submit", async function(event) {
            event.preventDefault();  // Prevent the default form submission
        
            const username = document.getElementById("username").value
            const password = document.getElementById("password").value
        
            try {
                const response = await fetch("/signin", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(
                        { 
                            'email': username, 
                            'password': password 
                        }
                    )
                });
        
                if (response.ok) {
                    const data = await response.json()
                    
                    location.reload()
                } else {
                    alert("Login failed: " + response.statusText)
                }
            } catch (error) {
                console.error("Error:", error)
                alert("An error occurred while logging in.")
            }
        });
    }
}

function add_event_register_form() {
    // We have the register button disabled, enabling once we loaded our javascript
    // THIS IS AN ISSUE, IF THE OTHER PARTY DOES NOT LOAD JAVASCRIPT
    var register_submit_btn = document.getElementById("register_submit")
    if(register_submit_btn) {
        register_submit_btn.disabled = false
    }
    var register_form = document.getElementById("register_form")
    if(register_form) {
        register_form.addEventListener("submit", async function(event) {
            event.preventDefault();  // Prevent the default form submission
        
            const username = document.getElementById("username").value
            const password = document.getElementById("password").value
        
            try {
                const response = await fetch("/register", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(
                        { 
                            'email': username, 
                            'password': password 
                        }
                    )
                });
        
                if (response.ok) {
                    var response_container = document.getElementById("response")
                    const data = await response.json()

                    if(data == "AlreadyExists") {
                        response_container.innerHTML = "Username already exist"
                    } else if(data == "PasswordTooShort") {
                        response_container.innerHTML = "Password is too short"
                    } else if(data == "Success") {
                        response_container.style.color = 'green'
                        response_container.innerHTML = "Successfully created a new account, redirecting to <a href='/'>Sign-in</a> in 5 seconds."
                        
                        await new Promise(r => setTimeout(r, 5000))
                        location.href = "/"
                    }
                } else {
                    alert("Register failed: " + response.statusText)
                }
            } catch (error) {
                console.error("Error:", error)
                alert("An error occurred while logging in.")
            }
        });
    }
}