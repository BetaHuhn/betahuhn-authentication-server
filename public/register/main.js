const email = document.getElementById('email-input'),
    passwd = document.getElementById('passwd-input'),
    name = document.getElementById('name-input'),
    error = document.getElementById('error')

async function register() {
    const data = {
        email: email.value,
        password: passwd.value,
        name: name.value
    };
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    };
    const response = await fetch('/auth/register', options);
    const json = await response.json();
    if (json.status == 400) {
        error.innerHTML = `<p id=text >Email not valid</p>`;
    } else if (json.status == 407) {
        error.innerHTML = `<p id=text >Email already in use</p>`;
    } else if (json.status == 404) {
        error.innerHTML = `<p id=text >Password has whitespace</p>`;
    } else if (json.status == 405) {
        error.innerHTML = `<p id=text >Password too long (max. 20)</p>`;
    } else if (json.status == 406) {
        error.innerHTML = `<p id=text >Password too short (min. 8)</p>`;
    } else if (json.status == 401) {
        error.innerHTML = `<p id=text >Password not valid. (Only A-z 0-9 !?)</p>`;
    } else if (json.status == 408) {
        error.innerHTML = `<p id=text >Please fill out every field!</p>`;
    } else if (json.status == 200) {
        console.log("registration success");
        window.location.replace("/");
    } else {
        error.innerHTML = `<p id=text >${json.status}: Es ist ein Fehler aufgetreten, bitte veruche es erneut. </p>`;
    }
}

passwd.addEventListener("keyup", function(event) {
    if (event.keyCode === 13) {
        event.preventDefault();
        document.getElementById("register-button").click();
    }
});