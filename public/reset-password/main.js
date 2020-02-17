//main.js - fck-afd URL shortener - Maximilian Schiller
var input = document.getElementById('url-input'),
    out = document.getElementById('out'),
    start = document.getElementById('start'),
    header = document.getElementById('header')

var email;

async function auth() {
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: email })
    };
    const response = await fetch('/auth/reset-password', options);
    const json = await response.json();
    if (json.status == 200) {
        console.log(json);
        start.innerHTML = `<h1>Bitte überprüfe dein Email Postfach: ${json.email}</h1>`;
        out.innerHTML = `<a class="bottom" href="/login"><button class="btn btn--primary uppercase">Login</button></a>`;
    } else if (json.status == 405) {
        start.innerHTML = `<h1>Diese Email-Adresse existiert nicht</h1>`;
    }else {
        start.innerHTML = `<h1>Es ist ein Fehler aufgetreten: ${json.status}</h1>`;
    }
}

async function run() {
    header.innerHTML = `<h1>Um dein Passwort zurück zu setzen musst \ndu zuerst deine Email-Adresse eingeben:</h1>`;
    start.innerHTML = `<input type="text" id="url-input" class="form__field" placeholder="Email">`;
    out.innerHTML = `<button class="btn btn--primary uppercase" onclick="confirm()">Check</button>`;
}

function confirm() {
    email = document.getElementById('url-input').value;
    header.removeChild(header.childNodes[0]);
    start.innerHTML = `<h1>Bist du sicher das du dein Passwort zurücksetzen willst? \nFalls ja, schicken wir dir eine Reset-Email an: ${email}</h1>`;
    out.innerHTML = `<button class="btn btn--primary uppercase" onclick="auth()">Zurücksetzen</button>`;
}