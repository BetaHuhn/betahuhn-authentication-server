const email = document.getElementById('email-input'),
    passwd = document.getElementById('passwd-input'),
    error = document.getElementById('error')

async function login() {
    var url_string = window.location.href
    var url = new URL(url_string);
    var ref = url.searchParams.get("ref");
    const data = {
        email: email.value,
        password: passwd.value,
        ref: ref
    };
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    };
    const response = await fetch('/auth/login', options);
    const json = await response.json();
    if (json.status == 408) {
        error.innerHTML = `<p id=text >Wrong password</p>`;
    } else if (json.status == 405) {
        error.innerHTML = `<p id=text >User does not exist</p>`;
    } else if (json.status == 200) {

        console.log("login success");
        if (ref == null) {
            window.location.replace("/");
        } else {
            console.log("Redirecting to " + ref)
            window.location.replace("https://" + ref);
        }
    } else {
        error.innerHTML = `<p id=text >${json.status}: Es ist ein Fehler aufgetreten, bitte veruche es erneut. </p>`;
    }
}

passwd.addEventListener("keyup", function(event) {
    if (event.keyCode === 13) {
        event.preventDefault();
        document.getElementById("login-button").click();
    }
});