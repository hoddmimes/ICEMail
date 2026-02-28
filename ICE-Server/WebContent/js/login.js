document.addEventListener("DOMContentLoaded", () => {
    login_init();
});

function validateUsername(username) {
    const pattern = /^[a-zA-Z][a-zA-Z0-9_]{2,31}$/;
    return pattern.test(username);
}

function login_init() {
    const btn = document.getElementById("login");
    const stsmsg = document.getElementById("StatusMessage");

    btn.addEventListener("click", async () => {
        stsmsg.textContent = "";
        stsmsg.className = "";

        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        if (isEmpty(username)) {
            stsmsg.textContent = "Username is required";
            stsmsg.className = "error";
            return;
        }

        if (!validateUsername(username)) {
            stsmsg.textContent = "Invalid username format";
            stsmsg.className = "error";
            return;
        }

        if (isEmpty(password)) {
            stsmsg.textContent = "Password is required";
            stsmsg.className = "error";
            return;
        }

        btn.disabled = true;

        try {
            const hPassword = await hashPassword(username, password);

            const jRequest = {
                'username': username.toLowerCase(),
                'password': hPassword
            };

            const jResponse = await callServer("/login", {
                method: "POST",
                body: JSON.stringify(jRequest)
            });

            if (jResponse) {
                stsmsg.textContent = jResponse.message;
                stsmsg.className = "success";
                // Store password in sessionStorage for client-side PGP decryption
                sessionStorage.setItem('password', password);
                if (username.toLowerCase() == 'admin') {
                    // User is successfully logged in. If the user is "admin" navigate to the admin-index.html page
                    loadPage('/admin/index.html');
                    } else {
                    // Otherwise there is a plain vanilla web mail user, so navigate to the web-mail.html
                    loadPage('/web/index.html');
                }
            } else {
                alert("Login failed. Please check your username and password.");
            }

        } catch (e) {
            stsmsg.textContent = "Login failed: " + e.message;
            stsmsg.className = "error";
        } finally {
            btn.disabled = false;
        }
    });
}
