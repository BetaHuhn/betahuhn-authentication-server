const header = document.getElementById('header'),
    start = document.getElementById('start'),
    name = document.getElementById('name'),
    button1 = document.getElementById('button1'),
    button2 = document.getElementById('button2'),
    button3 = document.getElementById('button3')

async function authenticate() {
    const options = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    };
    const response = await fetch('/auth/authorize', options);
    const json = await response.json();
    if (json.status == 200) {
        console.log(json.name);
        header.innerHTML = `<p>Hallo, ${json.name}</p>`;
        button1.innerHTML = `<a href="/logout"><button class="btn btn--primary uppercase">Logout</button></a>`;
        button2.innerHTML = `<a href="/new-password"><button class="btn btn--primary uppercase">Passwort Ändern</button></a>`;
    } else if (json.status == 300) {
        window.location.replace(json.redirect)
    } else {
        window.location.replace("/login")
    }
}

setInterval(async function() {
    location.replace(`/refresh?ref=${window.location}`);
}, 900 * 1000); // x * 1000 milsec